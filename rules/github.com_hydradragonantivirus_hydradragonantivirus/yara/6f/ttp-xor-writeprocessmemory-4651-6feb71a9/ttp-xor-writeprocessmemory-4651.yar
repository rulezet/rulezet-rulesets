rule TTP_XOR_WriteProcessMemory_4651 {
  strings:
    $key_4651 = { 11 23 [2] 23 01 [2] 25 34 [2] 0b 34 [2] 34 28 }

  condition:
    any of them
}