rule TTP_XOR_WriteProcessMemory_1515 {
  strings:
    $key_1515 = { 42 67 [2] 70 45 [2] 76 70 [2] 58 70 [2] 67 6c }

  condition:
    any of them
}