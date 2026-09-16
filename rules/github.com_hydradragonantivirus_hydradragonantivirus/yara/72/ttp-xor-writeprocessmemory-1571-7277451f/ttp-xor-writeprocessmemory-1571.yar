rule TTP_XOR_WriteProcessMemory_1571 {
  strings:
    $key_1571 = { 42 03 [2] 70 21 [2] 76 14 [2] 58 14 [2] 67 08 }

  condition:
    any of them
}