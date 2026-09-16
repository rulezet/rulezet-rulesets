rule TTP_XOR_WriteProcessMemory_3649 {
  strings:
    $key_3649 = { 61 3b [2] 53 19 [2] 55 2c [2] 7b 2c [2] 44 30 }

  condition:
    any of them
}