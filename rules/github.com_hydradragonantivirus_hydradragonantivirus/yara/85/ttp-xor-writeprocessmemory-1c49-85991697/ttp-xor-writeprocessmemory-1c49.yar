rule TTP_XOR_WriteProcessMemory_1c49 {
  strings:
    $key_1c49 = { 4b 3b [2] 79 19 [2] 7f 2c [2] 51 2c [2] 6e 30 }

  condition:
    any of them
}