rule TTP_XOR_WriteProcessMemory_5566 {
  strings:
    $key_5566 = { 02 14 [2] 30 36 [2] 36 03 [2] 18 03 [2] 27 1f }

  condition:
    any of them
}