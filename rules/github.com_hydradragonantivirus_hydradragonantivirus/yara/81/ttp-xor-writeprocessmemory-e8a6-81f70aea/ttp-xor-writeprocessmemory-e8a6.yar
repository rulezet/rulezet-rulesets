rule TTP_XOR_WriteProcessMemory_e8a6 {
  strings:
    $key_e8a6 = { bf d4 [2] 8d f6 [2] 8b c3 [2] a5 c3 [2] 9a df }

  condition:
    any of them
}