rule TTP_XOR_WriteProcessMemory_7749 {
  strings:
    $key_7749 = { 20 3b [2] 12 19 [2] 14 2c [2] 3a 2c [2] 05 30 }

  condition:
    any of them
}