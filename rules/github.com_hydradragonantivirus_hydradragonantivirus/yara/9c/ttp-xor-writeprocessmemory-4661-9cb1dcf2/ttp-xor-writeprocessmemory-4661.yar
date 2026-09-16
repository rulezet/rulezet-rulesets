rule TTP_XOR_WriteProcessMemory_4661 {
  strings:
    $key_4661 = { 11 13 [2] 23 31 [2] 25 04 [2] 0b 04 [2] 34 18 }

  condition:
    any of them
}