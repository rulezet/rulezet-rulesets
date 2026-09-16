rule TTP_XOR_WriteProcessMemory_1a49 {
  strings:
    $key_1a49 = { 4d 3b [2] 7f 19 [2] 79 2c [2] 57 2c [2] 68 30 }

  condition:
    any of them
}