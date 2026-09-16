rule TTP_XOR_WriteProcessMemory_b5f0 {
  strings:
    $key_b5f0 = { e2 82 [2] d0 a0 [2] d6 95 [2] f8 95 [2] c7 89 }

  condition:
    any of them
}