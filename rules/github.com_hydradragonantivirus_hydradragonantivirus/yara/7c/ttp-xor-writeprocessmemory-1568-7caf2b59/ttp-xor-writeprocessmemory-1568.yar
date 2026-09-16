rule TTP_XOR_WriteProcessMemory_1568 {
  strings:
    $key_1568 = { 42 1a [2] 70 38 [2] 76 0d [2] 58 0d [2] 67 11 }

  condition:
    any of them
}