rule TTP_XOR_WriteProcessMemory_7d8b {
  strings:
    $key_7d8b = { 2a f9 [2] 18 db [2] 1e ee [2] 30 ee [2] 0f f2 }

  condition:
    any of them
}