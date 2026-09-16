rule TTP_XOR_WriteProcessMemory_61b1 {
  strings:
    $key_61b1 = { 36 c3 [2] 04 e1 [2] 02 d4 [2] 2c d4 [2] 13 c8 }

  condition:
    any of them
}