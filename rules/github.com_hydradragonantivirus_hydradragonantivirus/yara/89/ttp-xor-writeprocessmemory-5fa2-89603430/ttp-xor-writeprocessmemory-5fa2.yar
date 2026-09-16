rule TTP_XOR_WriteProcessMemory_5fa2 {
  strings:
    $key_5fa2 = { 08 d0 [2] 3a f2 [2] 3c c7 [2] 12 c7 [2] 2d db }

  condition:
    any of them
}