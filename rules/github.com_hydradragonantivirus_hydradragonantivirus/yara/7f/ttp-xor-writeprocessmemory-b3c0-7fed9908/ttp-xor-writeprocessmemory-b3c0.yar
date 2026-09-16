rule TTP_XOR_WriteProcessMemory_b3c0 {
  strings:
    $key_b3c0 = { e4 b2 [2] d6 90 [2] d0 a5 [2] fe a5 [2] c1 b9 }

  condition:
    any of them
}