rule TTP_XOR_WriteProcessMemory_1fa2 {
  strings:
    $key_1fa2 = { 48 d0 [2] 7a f2 [2] 7c c7 [2] 52 c7 [2] 6d db }

  condition:
    any of them
}