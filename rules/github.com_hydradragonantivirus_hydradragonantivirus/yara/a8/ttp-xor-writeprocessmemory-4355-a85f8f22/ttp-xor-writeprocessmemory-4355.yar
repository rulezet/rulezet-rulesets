rule TTP_XOR_WriteProcessMemory_4355 {
  strings:
    $key_4355 = { 14 27 [2] 26 05 [2] 20 30 [2] 0e 30 [2] 31 2c }

  condition:
    any of them
}