rule TTP_XOR_WriteProcessMemory_a4e0 {
  strings:
    $key_a4e0 = { f3 92 [2] c1 b0 [2] c7 85 [2] e9 85 [2] d6 99 }

  condition:
    any of them
}