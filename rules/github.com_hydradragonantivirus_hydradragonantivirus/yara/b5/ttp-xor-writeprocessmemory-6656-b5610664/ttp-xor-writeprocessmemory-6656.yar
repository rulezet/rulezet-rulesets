rule TTP_XOR_WriteProcessMemory_6656 {
  strings:
    $key_6656 = { 31 24 [2] 03 06 [2] 05 33 [2] 2b 33 [2] 14 2f }

  condition:
    any of them
}