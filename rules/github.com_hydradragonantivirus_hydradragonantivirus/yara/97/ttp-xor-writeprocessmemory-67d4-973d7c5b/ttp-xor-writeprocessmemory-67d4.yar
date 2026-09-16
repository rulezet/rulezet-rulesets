rule TTP_XOR_WriteProcessMemory_67d4 {
  strings:
    $key_67d4 = { 30 a6 [2] 02 84 [2] 04 b1 [2] 2a b1 [2] 15 ad }

  condition:
    any of them
}