rule TTP_XOR_WriteProcessMemory_4662 {
  strings:
    $key_4662 = { 11 10 [2] 23 32 [2] 25 07 [2] 0b 07 [2] 34 1b }

  condition:
    any of them
}