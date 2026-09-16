rule TTP_XOR_WriteProcessMemory_a491 {
  strings:
    $key_a491 = { f3 e3 [2] c1 c1 [2] c7 f4 [2] e9 f4 [2] d6 e8 }

  condition:
    any of them
}