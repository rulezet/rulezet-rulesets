rule TTP_XOR_WriteProcessMemory_f666 {
  strings:
    $key_f666 = { a1 14 [2] 93 36 [2] 95 03 [2] bb 03 [2] 84 1f }

  condition:
    any of them
}