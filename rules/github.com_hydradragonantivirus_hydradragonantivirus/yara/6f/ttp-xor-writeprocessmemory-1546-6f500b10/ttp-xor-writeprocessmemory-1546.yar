rule TTP_XOR_WriteProcessMemory_1546 {
  strings:
    $key_1546 = { 42 34 [2] 70 16 [2] 76 23 [2] 58 23 [2] 67 3f }

  condition:
    any of them
}