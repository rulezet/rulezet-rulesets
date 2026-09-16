rule TTP_XOR_WriteProcessMemory_b1f0 {
  strings:
    $key_b1f0 = { e6 82 [2] d4 a0 [2] d2 95 [2] fc 95 [2] c3 89 }

  condition:
    any of them
}