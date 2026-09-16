rule TTP_XOR_WriteProcessMemory_1506 {
  strings:
    $key_1506 = { 42 74 [2] 70 56 [2] 76 63 [2] 58 63 [2] 67 7f }

  condition:
    any of them
}