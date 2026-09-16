rule TTP_XOR_WriteProcessMemory_7449 {
  strings:
    $key_7449 = { 23 3b [2] 11 19 [2] 17 2c [2] 39 2c [2] 06 30 }

  condition:
    any of them
}