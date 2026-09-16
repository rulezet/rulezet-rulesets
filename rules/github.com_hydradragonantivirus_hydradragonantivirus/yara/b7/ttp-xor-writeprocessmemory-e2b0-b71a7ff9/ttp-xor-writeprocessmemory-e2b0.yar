rule TTP_XOR_WriteProcessMemory_e2b0 {
  strings:
    $key_e2b0 = { b5 c2 [2] 87 e0 [2] 81 d5 [2] af d5 [2] 90 c9 }

  condition:
    any of them
}