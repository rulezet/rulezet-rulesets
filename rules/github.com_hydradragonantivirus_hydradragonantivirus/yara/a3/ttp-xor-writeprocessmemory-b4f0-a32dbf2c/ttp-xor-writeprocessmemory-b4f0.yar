rule TTP_XOR_WriteProcessMemory_b4f0 {
  strings:
    $key_b4f0 = { e3 82 [2] d1 a0 [2] d7 95 [2] f9 95 [2] c6 89 }

  condition:
    any of them
}