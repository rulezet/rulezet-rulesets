rule TTP_XOR_WriteProcessMemory_6666 {
  strings:
    $key_6666 = { 31 14 [2] 03 36 [2] 05 03 [2] 2b 03 [2] 14 1f }

  condition:
    any of them
}