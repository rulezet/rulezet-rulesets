rule TTP_XOR_WriteProcessMemory_1541 {
  strings:
    $key_1541 = { 42 33 [2] 70 11 [2] 76 24 [2] 58 24 [2] 67 38 }

  condition:
    any of them
}