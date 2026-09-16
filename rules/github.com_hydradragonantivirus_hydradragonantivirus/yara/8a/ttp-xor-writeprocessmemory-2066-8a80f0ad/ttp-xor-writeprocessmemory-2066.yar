rule TTP_XOR_WriteProcessMemory_2066 {
  strings:
    $key_2066 = { 77 14 [2] 45 36 [2] 43 03 [2] 6d 03 [2] 52 1f }

  condition:
    any of them
}