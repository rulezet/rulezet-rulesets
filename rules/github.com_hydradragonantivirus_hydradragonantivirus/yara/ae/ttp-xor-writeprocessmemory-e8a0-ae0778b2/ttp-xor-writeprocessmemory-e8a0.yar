rule TTP_XOR_WriteProcessMemory_e8a0 {
  strings:
    $key_e8a0 = { bf d2 [2] 8d f0 [2] 8b c5 [2] a5 c5 [2] 9a d9 }

  condition:
    any of them
}