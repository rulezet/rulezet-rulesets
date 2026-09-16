rule TTP_XOR_WriteProcessMemory_4a8b {
  strings:
    $key_4a8b = { 1d f9 [2] 2f db [2] 29 ee [2] 07 ee [2] 38 f2 }

  condition:
    any of them
}