rule TTP_XOR_WriteProcessMemory_4456 {
  strings:
    $key_4456 = { 13 24 [2] 21 06 [2] 27 33 [2] 09 33 [2] 36 2f }

  condition:
    any of them
}