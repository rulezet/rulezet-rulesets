rule TTP_XOR_WriteProcessMemory_75b4 {
  strings:
    $key_75b4 = { 22 c6 [2] 10 e4 [2] 16 d1 [2] 38 d1 [2] 07 cd }

  condition:
    any of them
}