rule TTP_XOR_WriteProcessMemory_67d1 {
  strings:
    $key_67d1 = { 30 a3 [2] 02 81 [2] 04 b4 [2] 2a b4 [2] 15 a8 }

  condition:
    any of them
}