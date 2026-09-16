rule TTP_XOR_WriteProcessMemory_b3f0 {
  strings:
    $key_b3f0 = { e4 82 [2] d6 a0 [2] d0 95 [2] fe 95 [2] c1 89 }

  condition:
    any of them
}