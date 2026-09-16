rule TTP_XOR_WriteProcessMemory_2f8b {
  strings:
    $key_2f8b = { 78 f9 [2] 4a db [2] 4c ee [2] 62 ee [2] 5d f2 }

  condition:
    any of them
}