rule TTP_XOR_WriteProcessMemory_b3f5 {
  strings:
    $key_b3f5 = { e4 87 [2] d6 a5 [2] d0 90 [2] fe 90 [2] c1 8c }

  condition:
    any of them
}