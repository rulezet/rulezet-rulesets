rule TTP_XOR_WriteProcessMemory_1544 {
  strings:
    $key_1544 = { 42 36 [2] 70 14 [2] 76 21 [2] 58 21 [2] 67 3d }

  condition:
    any of them
}