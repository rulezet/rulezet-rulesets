rule TTP_XOR_WriteProcessMemory_b366 {
  strings:
    $key_b366 = { e4 14 [2] d6 36 [2] d0 03 [2] fe 03 [2] c1 1f }

  condition:
    any of them
}