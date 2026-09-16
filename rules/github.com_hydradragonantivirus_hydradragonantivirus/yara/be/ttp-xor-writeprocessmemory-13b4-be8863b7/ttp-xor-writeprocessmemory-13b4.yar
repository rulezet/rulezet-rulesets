rule TTP_XOR_WriteProcessMemory_13b4 {
  strings:
    $key_13b4 = { 44 c6 [2] 76 e4 [2] 70 d1 [2] 5e d1 [2] 61 cd }

  condition:
    any of them
}