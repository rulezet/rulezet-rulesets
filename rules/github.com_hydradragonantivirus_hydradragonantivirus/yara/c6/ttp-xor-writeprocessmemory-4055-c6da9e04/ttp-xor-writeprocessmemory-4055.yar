rule TTP_XOR_WriteProcessMemory_4055 {
  strings:
    $key_4055 = { 17 27 [2] 25 05 [2] 23 30 [2] 0d 30 [2] 32 2c }

  condition:
    any of them
}