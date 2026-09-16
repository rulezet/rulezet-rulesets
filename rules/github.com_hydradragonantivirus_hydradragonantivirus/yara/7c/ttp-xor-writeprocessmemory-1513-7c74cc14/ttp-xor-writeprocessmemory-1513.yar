rule TTP_XOR_WriteProcessMemory_1513 {
  strings:
    $key_1513 = { 42 61 [2] 70 43 [2] 76 76 [2] 58 76 [2] 67 6a }

  condition:
    any of them
}