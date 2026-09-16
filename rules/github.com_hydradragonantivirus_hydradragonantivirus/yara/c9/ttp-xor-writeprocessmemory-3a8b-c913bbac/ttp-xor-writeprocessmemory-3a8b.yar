rule TTP_XOR_WriteProcessMemory_3a8b {
  strings:
    $key_3a8b = { 6d f9 [2] 5f db [2] 59 ee [2] 77 ee [2] 48 f2 }

  condition:
    any of them
}