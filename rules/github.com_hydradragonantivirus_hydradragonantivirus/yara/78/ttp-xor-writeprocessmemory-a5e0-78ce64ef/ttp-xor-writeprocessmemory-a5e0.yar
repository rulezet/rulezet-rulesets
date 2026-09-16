rule TTP_XOR_WriteProcessMemory_a5e0 {
  strings:
    $key_a5e0 = { f2 92 [2] c0 b0 [2] c6 85 [2] e8 85 [2] d7 99 }

  condition:
    any of them
}