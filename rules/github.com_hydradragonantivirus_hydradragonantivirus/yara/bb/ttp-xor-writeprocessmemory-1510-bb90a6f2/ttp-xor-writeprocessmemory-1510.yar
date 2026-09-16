rule TTP_XOR_WriteProcessMemory_1510 {
  strings:
    $key_1510 = { 42 62 [2] 70 40 [2] 76 75 [2] 58 75 [2] 67 69 }

  condition:
    any of them
}