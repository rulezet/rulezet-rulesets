rule TTP_XOR_WriteProcessMemory_2549 {
  strings:
    $key_2549 = { 72 3b [2] 40 19 [2] 46 2c [2] 68 2c [2] 57 30 }

  condition:
    any of them
}