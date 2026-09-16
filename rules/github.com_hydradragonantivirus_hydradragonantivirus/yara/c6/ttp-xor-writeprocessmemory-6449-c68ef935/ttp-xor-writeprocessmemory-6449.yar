rule TTP_XOR_WriteProcessMemory_6449 {
  strings:
    $key_6449 = { 33 3b [2] 01 19 [2] 07 2c [2] 29 2c [2] 16 30 }

  condition:
    any of them
}