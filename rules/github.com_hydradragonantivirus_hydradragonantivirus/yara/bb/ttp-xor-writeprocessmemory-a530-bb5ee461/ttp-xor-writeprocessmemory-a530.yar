rule TTP_XOR_WriteProcessMemory_a530 {
  strings:
    $key_a530 = { f2 42 [2] c0 60 [2] c6 55 [2] e8 55 [2] d7 49 }

  condition:
    any of them
}