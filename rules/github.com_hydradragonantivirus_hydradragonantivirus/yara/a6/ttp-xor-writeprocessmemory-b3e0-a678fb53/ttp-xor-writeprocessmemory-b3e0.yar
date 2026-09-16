rule TTP_XOR_WriteProcessMemory_b3e0 {
  strings:
    $key_b3e0 = { e4 92 [2] d6 b0 [2] d0 85 [2] fe 85 [2] c1 99 }

  condition:
    any of them
}