rule TTP_XOR_WriteProcessMemory_43b4 {
  strings:
    $key_43b4 = { 14 c6 [2] 26 e4 [2] 20 d1 [2] 0e d1 [2] 31 cd }

  condition:
    any of them
}