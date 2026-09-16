rule TTP_XOR_WriteProcessMemory_0d8b {
  strings:
    $key_0d8b = { 5a f9 [2] 68 db [2] 6e ee [2] 40 ee [2] 7f f2 }

  condition:
    any of them
}