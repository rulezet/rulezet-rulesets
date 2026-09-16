rule TTP_XOR_WriteProcessMemory_e2b1 {
  strings:
    $key_e2b1 = { b5 c3 [2] 87 e1 [2] 81 d4 [2] af d4 [2] 90 c8 }

  condition:
    any of them
}