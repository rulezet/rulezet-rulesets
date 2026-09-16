rule TTP_XOR_WriteProcessMemory_1184 {
  strings:
    $key_1184 = { 46 f6 [2] 74 d4 [2] 72 e1 [2] 5c e1 [2] 63 fd }

  condition:
    any of them
}