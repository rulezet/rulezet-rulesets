rule TTP_XOR_WriteProcessMemory_1524 {
  strings:
    $key_1524 = { 42 56 [2] 70 74 [2] 76 41 [2] 58 41 [2] 67 5d }

  condition:
    any of them
}