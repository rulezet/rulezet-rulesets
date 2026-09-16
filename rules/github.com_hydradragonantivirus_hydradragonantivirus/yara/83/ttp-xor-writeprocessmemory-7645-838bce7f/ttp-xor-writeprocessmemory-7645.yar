rule TTP_XOR_WriteProcessMemory_7645 {
  strings:
    $key_7645 = { 21 37 [2] 13 15 [2] 15 20 [2] 3b 20 [2] 04 3c }

  condition:
    any of them
}