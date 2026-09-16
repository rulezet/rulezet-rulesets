rule TTP_XOR_WriteProcessMemory_4066 {
  strings:
    $key_4066 = { 17 14 [2] 25 36 [2] 23 03 [2] 0d 03 [2] 32 1f }

  condition:
    any of them
}