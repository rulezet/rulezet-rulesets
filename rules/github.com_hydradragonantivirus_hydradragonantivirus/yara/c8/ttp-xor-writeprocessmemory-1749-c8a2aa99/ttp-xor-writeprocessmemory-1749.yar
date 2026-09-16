rule TTP_XOR_WriteProcessMemory_1749 {
  strings:
    $key_1749 = { 40 3b [2] 72 19 [2] 74 2c [2] 5a 2c [2] 65 30 }

  condition:
    any of them
}