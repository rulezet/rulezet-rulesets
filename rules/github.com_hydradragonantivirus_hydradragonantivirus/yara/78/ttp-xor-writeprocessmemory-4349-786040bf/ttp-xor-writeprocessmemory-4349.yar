rule TTP_XOR_WriteProcessMemory_4349 {
  strings:
    $key_4349 = { 14 3b [2] 26 19 [2] 20 2c [2] 0e 2c [2] 31 30 }

  condition:
    any of them
}