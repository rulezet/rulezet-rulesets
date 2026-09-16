rule TTP_XOR_WriteProcessMemory_1992 {
  strings:
    $key_1992 = { 4e e0 [2] 7c c2 [2] 7a f7 [2] 54 f7 [2] 6b eb }

  condition:
    any of them
}