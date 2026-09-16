rule TTP_XOR_WriteProcessMemory_6766 {
  strings:
    $key_6766 = { 30 14 [2] 02 36 [2] 04 03 [2] 2a 03 [2] 15 1f }

  condition:
    any of them
}