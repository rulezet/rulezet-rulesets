rule TTP_XOR_WriteProcessMemory_b3f7 {
  strings:
    $key_b3f7 = { e4 85 [2] d6 a7 [2] d0 92 [2] fe 92 [2] c1 8e }

  condition:
    any of them
}