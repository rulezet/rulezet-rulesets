rule TTP_XOR_WriteProcessMemory_0992 {
  strings:
    $key_0992 = { 5e e0 [2] 6c c2 [2] 6a f7 [2] 44 f7 [2] 7b eb }

  condition:
    any of them
}