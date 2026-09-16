rule TTP_XOR_WriteProcessMemory_7656 {
  strings:
    $key_7656 = { 21 24 [2] 13 06 [2] 15 33 [2] 3b 33 [2] 04 2f }

  condition:
    any of them
}