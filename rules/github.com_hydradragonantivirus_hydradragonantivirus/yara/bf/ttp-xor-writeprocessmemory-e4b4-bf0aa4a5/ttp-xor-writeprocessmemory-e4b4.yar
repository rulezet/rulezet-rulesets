rule TTP_XOR_WriteProcessMemory_e4b4 {
  strings:
    $key_e4b4 = { b3 c6 [2] 81 e4 [2] 87 d1 [2] a9 d1 [2] 96 cd }

  condition:
    any of them
}