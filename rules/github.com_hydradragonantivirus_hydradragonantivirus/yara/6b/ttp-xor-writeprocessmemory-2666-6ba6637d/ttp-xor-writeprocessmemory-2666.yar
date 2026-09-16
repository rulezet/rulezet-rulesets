rule TTP_XOR_WriteProcessMemory_2666 {
  strings:
    $key_2666 = { 71 14 [2] 43 36 [2] 45 03 [2] 6b 03 [2] 54 1f }

  condition:
    any of them
}