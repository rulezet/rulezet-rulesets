rule TTP_XOR_WriteProcessMemory_4992 {
  strings:
    $key_4992 = { 1e e0 [2] 2c c2 [2] 2a f7 [2] 04 f7 [2] 3b eb }

  condition:
    any of them
}