rule TTP_XOR_WriteProcessMemory_1540 {
  strings:
    $key_1540 = { 42 32 [2] 70 10 [2] 76 25 [2] 58 25 [2] 67 39 }

  condition:
    any of them
}