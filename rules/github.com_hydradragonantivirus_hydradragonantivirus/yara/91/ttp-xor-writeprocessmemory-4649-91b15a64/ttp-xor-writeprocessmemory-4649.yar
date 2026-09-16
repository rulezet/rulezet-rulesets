rule TTP_XOR_WriteProcessMemory_4649 {
  strings:
    $key_4649 = { 11 3b [2] 23 19 [2] 25 2c [2] 0b 2c [2] 34 30 }

  condition:
    any of them
}