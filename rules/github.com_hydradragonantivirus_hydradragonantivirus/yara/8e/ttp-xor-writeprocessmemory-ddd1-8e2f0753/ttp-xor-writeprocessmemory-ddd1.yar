rule TTP_XOR_WriteProcessMemory_ddd1 {
  strings:
    $key_ddd1 = { 8a a3 [2] b8 81 [2] be b4 [2] 90 b4 [2] af a8 }

  condition:
    any of them
}