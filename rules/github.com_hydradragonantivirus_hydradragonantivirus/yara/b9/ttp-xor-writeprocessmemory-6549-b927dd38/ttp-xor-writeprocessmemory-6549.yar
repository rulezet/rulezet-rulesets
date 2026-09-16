rule TTP_XOR_WriteProcessMemory_6549 {
  strings:
    $key_6549 = { 32 3b [2] 00 19 [2] 06 2c [2] 28 2c [2] 17 30 }

  condition:
    any of them
}