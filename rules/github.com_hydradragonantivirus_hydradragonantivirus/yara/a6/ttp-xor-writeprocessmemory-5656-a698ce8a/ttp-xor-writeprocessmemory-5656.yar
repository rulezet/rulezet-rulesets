rule TTP_XOR_WriteProcessMemory_5656 {
  strings:
    $key_5656 = { 01 24 [2] 33 06 [2] 35 33 [2] 1b 33 [2] 24 2f }

  condition:
    any of them
}