rule TTP_XOR_WriteProcessMemory_7a8b {
  strings:
    $key_7a8b = { 2d f9 [2] 1f db [2] 19 ee [2] 37 ee [2] 08 f2 }

  condition:
    any of them
}