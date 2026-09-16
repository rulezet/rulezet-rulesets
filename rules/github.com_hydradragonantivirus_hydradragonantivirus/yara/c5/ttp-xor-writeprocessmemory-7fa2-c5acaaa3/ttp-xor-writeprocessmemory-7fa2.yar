rule TTP_XOR_WriteProcessMemory_7fa2 {
  strings:
    $key_7fa2 = { 28 d0 [2] 1a f2 [2] 1c c7 [2] 32 c7 [2] 0d db }

  condition:
    any of them
}