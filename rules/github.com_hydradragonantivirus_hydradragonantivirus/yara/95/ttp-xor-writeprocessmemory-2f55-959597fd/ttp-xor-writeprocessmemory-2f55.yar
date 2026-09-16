rule TTP_XOR_WriteProcessMemory_2f55 {
  strings:
    $key_2f55 = { 78 27 [2] 4a 05 [2] 4c 30 [2] 62 30 [2] 5d 2c }

  condition:
    any of them
}