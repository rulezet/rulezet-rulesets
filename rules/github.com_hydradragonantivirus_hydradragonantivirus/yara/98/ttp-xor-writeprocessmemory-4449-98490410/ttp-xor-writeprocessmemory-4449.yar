rule TTP_XOR_WriteProcessMemory_4449 {
  strings:
    $key_4449 = { 13 3b [2] 21 19 [2] 27 2c [2] 09 2c [2] 36 30 }

  condition:
    any of them
}