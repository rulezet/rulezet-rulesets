rule TTP_XOR_WriteProcessMemory_a4c0 {
  strings:
    $key_a4c0 = { f3 b2 [2] c1 90 [2] c7 a5 [2] e9 a5 [2] d6 b9 }

  condition:
    any of them
}