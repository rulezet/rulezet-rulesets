rule TTP_XOR_WriteProcessMemory_6084 {
  strings:
    $key_6084 = { 37 f6 [2] 05 d4 [2] 03 e1 [2] 2d e1 [2] 12 fd }

  condition:
    any of them
}