rule TTP_XOR_WriteProcessMemory_15d1 {
  strings:
    $key_15d1 = { 42 a3 [2] 70 81 [2] 76 b4 [2] 58 b4 [2] 67 a8 }

  condition:
    any of them
}