rule TTP_XOR_WriteProcessMemory_e8a2 {
  strings:
    $key_e8a2 = { bf d0 [2] 8d f2 [2] 8b c7 [2] a5 c7 [2] 9a db }

  condition:
    any of them
}