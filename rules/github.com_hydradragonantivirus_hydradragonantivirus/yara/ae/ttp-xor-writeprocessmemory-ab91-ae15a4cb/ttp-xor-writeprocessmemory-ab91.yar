rule TTP_XOR_WriteProcessMemory_ab91 {
  strings:
    $key_ab91 = { fc e3 [2] ce c1 [2] c8 f4 [2] e6 f4 [2] d9 e8 }

  condition:
    any of them
}