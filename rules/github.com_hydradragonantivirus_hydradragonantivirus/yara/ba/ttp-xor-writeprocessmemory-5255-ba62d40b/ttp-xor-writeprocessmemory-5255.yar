rule TTP_XOR_WriteProcessMemory_5255 {
  strings:
    $key_5255 = { 05 27 [2] 37 05 [2] 31 30 [2] 1f 30 [2] 20 2c }

  condition:
    any of them
}