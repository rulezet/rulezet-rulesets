rule TTP_XOR_WriteProcessMemory_e584 {
  strings:
    $key_e584 = { b2 f6 [2] 80 d4 [2] 86 e1 [2] a8 e1 [2] 97 fd }

  condition:
    any of them
}