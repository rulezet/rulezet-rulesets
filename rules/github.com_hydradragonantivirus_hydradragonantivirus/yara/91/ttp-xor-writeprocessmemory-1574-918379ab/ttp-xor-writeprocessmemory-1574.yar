rule TTP_XOR_WriteProcessMemory_1574 {
  strings:
    $key_1574 = { 42 06 [2] 70 24 [2] 76 11 [2] 58 11 [2] 67 0d }

  condition:
    any of them
}