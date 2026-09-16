rule TTP_XOR_WriteProcessMemory_5f55 {
  strings:
    $key_5f55 = { 08 27 [2] 3a 05 [2] 3c 30 [2] 12 30 [2] 2d 2c }

  condition:
    any of them
}