rule TTP_XOR_WriteProcessMemory_77b4 {
  strings:
    $key_77b4 = { 20 c6 [2] 12 e4 [2] 14 d1 [2] 3a d1 [2] 05 cd }

  condition:
    any of them
}