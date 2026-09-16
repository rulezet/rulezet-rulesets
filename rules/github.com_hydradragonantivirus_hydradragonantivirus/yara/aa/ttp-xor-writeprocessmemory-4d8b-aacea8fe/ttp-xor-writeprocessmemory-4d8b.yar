rule TTP_XOR_WriteProcessMemory_4d8b {
  strings:
    $key_4d8b = { 1a f9 [2] 28 db [2] 2e ee [2] 00 ee [2] 3f f2 }

  condition:
    any of them
}