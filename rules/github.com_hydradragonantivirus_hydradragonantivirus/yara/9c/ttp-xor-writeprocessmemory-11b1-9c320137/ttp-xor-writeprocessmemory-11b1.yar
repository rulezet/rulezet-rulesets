rule TTP_XOR_WriteProcessMemory_11b1 {
  strings:
    $key_11b1 = { 46 c3 [2] 74 e1 [2] 72 d4 [2] 5c d4 [2] 63 c8 }

  condition:
    any of them
}