rule TTP_XOR_WriteProcessMemory_47b4 {
  strings:
    $key_47b4 = { 10 c6 [2] 22 e4 [2] 24 d1 [2] 0a d1 [2] 35 cd }

  condition:
    any of them
}