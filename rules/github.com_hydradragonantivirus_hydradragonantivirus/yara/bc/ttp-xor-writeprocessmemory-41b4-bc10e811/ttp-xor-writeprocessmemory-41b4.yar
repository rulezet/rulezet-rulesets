rule TTP_XOR_WriteProcessMemory_41b4 {
  strings:
    $key_41b4 = { 16 c6 [2] 24 e4 [2] 22 d1 [2] 0c d1 [2] 33 cd }

  condition:
    any of them
}