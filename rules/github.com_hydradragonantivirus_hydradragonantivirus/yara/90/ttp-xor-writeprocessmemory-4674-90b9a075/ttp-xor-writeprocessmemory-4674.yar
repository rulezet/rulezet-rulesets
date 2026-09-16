rule TTP_XOR_WriteProcessMemory_4674 {
  strings:
    $key_4674 = { 11 06 [2] 23 24 [2] 25 11 [2] 0b 11 [2] 34 0d }

  condition:
    any of them
}