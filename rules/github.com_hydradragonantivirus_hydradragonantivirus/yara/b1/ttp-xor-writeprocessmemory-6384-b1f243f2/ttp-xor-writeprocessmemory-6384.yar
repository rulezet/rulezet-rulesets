rule TTP_XOR_WriteProcessMemory_6384 {
  strings:
    $key_6384 = { 34 f6 [2] 06 d4 [2] 00 e1 [2] 2e e1 [2] 11 fd }

  condition:
    any of them
}