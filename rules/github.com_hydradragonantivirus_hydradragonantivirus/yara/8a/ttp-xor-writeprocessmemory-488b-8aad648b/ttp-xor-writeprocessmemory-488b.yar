rule TTP_XOR_WriteProcessMemory_488b {
  strings:
    $key_488b = { 1f f9 [2] 2d db [2] 2b ee [2] 05 ee [2] 3a f2 }

  condition:
    any of them
}