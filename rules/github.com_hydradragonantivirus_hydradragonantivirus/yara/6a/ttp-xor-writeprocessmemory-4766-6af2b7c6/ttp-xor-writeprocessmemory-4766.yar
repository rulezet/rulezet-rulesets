rule TTP_XOR_WriteProcessMemory_4766 {
  strings:
    $key_4766 = { 10 14 [2] 22 36 [2] 24 03 [2] 0a 03 [2] 35 1f }

  condition:
    any of them
}