rule TTP_XOR_WriteProcessMemory_da82 {
  strings:
    $key_da82 = { 8d f0 [2] bf d2 [2] b9 e7 [2] 97 e7 [2] a8 fb }

  condition:
    any of them
}