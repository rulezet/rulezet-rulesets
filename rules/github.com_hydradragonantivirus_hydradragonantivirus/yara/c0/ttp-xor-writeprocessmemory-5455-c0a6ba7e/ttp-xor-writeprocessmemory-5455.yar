rule TTP_XOR_WriteProcessMemory_5455 {
  strings:
    $key_5455 = { 03 27 [2] 31 05 [2] 37 30 [2] 19 30 [2] 26 2c }

  condition:
    any of them
}