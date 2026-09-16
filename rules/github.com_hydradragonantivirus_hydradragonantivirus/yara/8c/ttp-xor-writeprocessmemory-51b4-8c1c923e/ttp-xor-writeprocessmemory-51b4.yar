rule TTP_XOR_WriteProcessMemory_51b4 {
  strings:
    $key_51b4 = { 06 c6 [2] 34 e4 [2] 32 d1 [2] 1c d1 [2] 23 cd }

  condition:
    any of them
}