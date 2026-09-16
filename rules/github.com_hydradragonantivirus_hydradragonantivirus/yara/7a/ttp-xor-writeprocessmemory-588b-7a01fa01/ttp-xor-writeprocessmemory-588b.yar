rule TTP_XOR_WriteProcessMemory_588b {
  strings:
    $key_588b = { 0f f9 [2] 3d db [2] 3b ee [2] 15 ee [2] 2a f2 }

  condition:
    any of them
}