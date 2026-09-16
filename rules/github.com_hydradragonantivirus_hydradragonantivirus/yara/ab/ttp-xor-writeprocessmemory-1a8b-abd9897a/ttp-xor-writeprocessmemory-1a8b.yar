rule TTP_XOR_WriteProcessMemory_1a8b {
  strings:
    $key_1a8b = { 4d f9 [2] 7f db [2] 79 ee [2] 57 ee [2] 68 f2 }

  condition:
    any of them
}