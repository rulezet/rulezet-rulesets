rule TTP_XOR_WriteProcessMemory_e5b1 {
  strings:
    $key_e5b1 = { b2 c3 [2] 80 e1 [2] 86 d4 [2] a8 d4 [2] 97 c8 }

  condition:
    any of them
}