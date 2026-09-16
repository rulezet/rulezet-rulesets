rule TTP_XOR_WriteProcessMemory_6f8b {
  strings:
    $key_6f8b = { 38 f9 [2] 0a db [2] 0c ee [2] 22 ee [2] 1d f2 }

  condition:
    any of them
}