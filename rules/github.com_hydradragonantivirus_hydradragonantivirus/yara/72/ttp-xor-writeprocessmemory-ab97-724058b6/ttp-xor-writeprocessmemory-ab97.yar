rule TTP_XOR_WriteProcessMemory_ab97 {
  strings:
    $key_ab97 = { fc e5 [2] ce c7 [2] c8 f2 [2] e6 f2 [2] d9 ee }

  condition:
    any of them
}