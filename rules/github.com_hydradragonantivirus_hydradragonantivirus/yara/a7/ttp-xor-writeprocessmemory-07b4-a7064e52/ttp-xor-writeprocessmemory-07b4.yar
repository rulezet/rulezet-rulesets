rule TTP_XOR_WriteProcessMemory_07b4 {
  strings:
    $key_07b4 = { 50 c6 [2] 62 e4 [2] 64 d1 [2] 4a d1 [2] 75 cd }

  condition:
    any of them
}