rule TTP_XOR_WriteProcessMemory_da87 {
  strings:
    $key_da87 = { 8d f5 [2] bf d7 [2] b9 e2 [2] 97 e2 [2] a8 fe }

  condition:
    any of them
}