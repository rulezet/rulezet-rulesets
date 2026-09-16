rule TTP_XOR_WriteProcessMemory_43b1 {
  strings:
    $key_43b1 = { 14 c3 [2] 26 e1 [2] 20 d4 [2] 0e d4 [2] 31 c8 }

  condition:
    any of them
}