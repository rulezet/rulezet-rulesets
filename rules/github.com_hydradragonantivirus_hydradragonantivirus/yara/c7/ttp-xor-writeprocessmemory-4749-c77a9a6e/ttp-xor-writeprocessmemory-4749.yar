rule TTP_XOR_WriteProcessMemory_4749 {
  strings:
    $key_4749 = { 10 3b [2] 22 19 [2] 24 2c [2] 0a 2c [2] 35 30 }

  condition:
    any of them
}