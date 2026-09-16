rule TTP_XOR_WriteProcessMemory_5066 {
  strings:
    $key_5066 = { 07 14 [2] 35 36 [2] 33 03 [2] 1d 03 [2] 22 1f }

  condition:
    any of them
}