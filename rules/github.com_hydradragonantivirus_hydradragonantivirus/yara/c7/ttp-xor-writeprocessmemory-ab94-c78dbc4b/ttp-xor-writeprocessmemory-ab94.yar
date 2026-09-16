rule TTP_XOR_WriteProcessMemory_ab94 {
  strings:
    $key_ab94 = { fc e6 [2] ce c4 [2] c8 f1 [2] e6 f1 [2] d9 ed }

  condition:
    any of them
}