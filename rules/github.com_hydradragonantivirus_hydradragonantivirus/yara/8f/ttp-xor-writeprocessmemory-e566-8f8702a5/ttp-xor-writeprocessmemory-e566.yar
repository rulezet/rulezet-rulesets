rule TTP_XOR_WriteProcessMemory_e566 {
  strings:
    $key_e566 = { b2 14 [2] 80 36 [2] 86 03 [2] a8 03 [2] 97 1f }

  condition:
    any of them
}