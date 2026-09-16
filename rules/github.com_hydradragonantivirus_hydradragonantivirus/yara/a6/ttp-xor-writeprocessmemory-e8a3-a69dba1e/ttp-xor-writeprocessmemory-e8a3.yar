rule TTP_XOR_WriteProcessMemory_e8a3 {
  strings:
    $key_e8a3 = { bf d1 [2] 8d f3 [2] 8b c6 [2] a5 c6 [2] 9a da }

  condition:
    any of them
}