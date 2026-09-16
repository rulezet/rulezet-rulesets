rule TTP_XOR_WriteProcessMemory_6992 {
  strings:
    $key_6992 = { 3e e0 [2] 0c c2 [2] 0a f7 [2] 24 f7 [2] 1b eb }

  condition:
    any of them
}