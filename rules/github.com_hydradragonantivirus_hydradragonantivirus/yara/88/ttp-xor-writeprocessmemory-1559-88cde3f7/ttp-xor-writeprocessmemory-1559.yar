rule TTP_XOR_WriteProcessMemory_1559 {
  strings:
    $key_1559 = { 42 2b [2] 70 09 [2] 76 3c [2] 58 3c [2] 67 20 }

  condition:
    any of them
}