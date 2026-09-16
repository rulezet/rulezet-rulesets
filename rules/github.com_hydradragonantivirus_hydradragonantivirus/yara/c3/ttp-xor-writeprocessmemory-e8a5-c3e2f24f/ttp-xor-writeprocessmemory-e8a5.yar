rule TTP_XOR_WriteProcessMemory_e8a5 {
  strings:
    $key_e8a5 = { bf d7 [2] 8d f5 [2] 8b c0 [2] a5 c0 [2] 9a dc }

  condition:
    any of them
}