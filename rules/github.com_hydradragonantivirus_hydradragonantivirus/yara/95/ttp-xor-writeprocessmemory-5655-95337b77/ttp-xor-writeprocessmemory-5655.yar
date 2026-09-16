rule TTP_XOR_WriteProcessMemory_5655 {
  strings:
    $key_5655 = { 01 27 [2] 33 05 [2] 35 30 [2] 1b 30 [2] 24 2c }

  condition:
    any of them
}