rule TTP_XOR_WriteProcessMemory_3549 {
  strings:
    $key_3549 = { 62 3b [2] 50 19 [2] 56 2c [2] 78 2c [2] 47 30 }

  condition:
    any of them
}