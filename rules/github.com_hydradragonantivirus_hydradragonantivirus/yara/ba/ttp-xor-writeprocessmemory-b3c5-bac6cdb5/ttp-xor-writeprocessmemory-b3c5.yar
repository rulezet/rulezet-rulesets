rule TTP_XOR_WriteProcessMemory_b3c5 {
  strings:
    $key_b3c5 = { e4 b7 [2] d6 95 [2] d0 a0 [2] fe a0 [2] c1 bc }

  condition:
    any of them
}