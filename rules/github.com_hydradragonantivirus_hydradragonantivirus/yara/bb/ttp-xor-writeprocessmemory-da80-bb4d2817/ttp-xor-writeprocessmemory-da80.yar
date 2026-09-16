rule TTP_XOR_WriteProcessMemory_da80 {
  strings:
    $key_da80 = { 8d f2 [2] bf d0 [2] b9 e5 [2] 97 e5 [2] a8 f9 }

  condition:
    any of them
}