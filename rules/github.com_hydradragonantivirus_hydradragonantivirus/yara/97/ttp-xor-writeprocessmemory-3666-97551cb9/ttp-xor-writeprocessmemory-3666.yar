rule TTP_XOR_WriteProcessMemory_3666 {
  strings:
    $key_3666 = { 61 14 [2] 53 36 [2] 55 03 [2] 7b 03 [2] 44 1f }

  condition:
    any of them
}