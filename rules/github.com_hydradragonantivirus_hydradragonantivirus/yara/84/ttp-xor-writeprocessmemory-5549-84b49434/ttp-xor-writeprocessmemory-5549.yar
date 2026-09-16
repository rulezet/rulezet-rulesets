rule TTP_XOR_WriteProcessMemory_5549 {
  strings:
    $key_5549 = { 02 3b [2] 30 19 [2] 36 2c [2] 18 2c [2] 27 30 }

  condition:
    any of them
}