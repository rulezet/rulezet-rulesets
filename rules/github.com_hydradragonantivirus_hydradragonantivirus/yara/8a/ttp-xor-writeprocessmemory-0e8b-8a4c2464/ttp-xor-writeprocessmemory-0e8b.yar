rule TTP_XOR_WriteProcessMemory_0e8b {
  strings:
    $key_0e8b = { 59 f9 [2] 6b db [2] 6d ee [2] 43 ee [2] 7c f2 }

  condition:
    any of them
}