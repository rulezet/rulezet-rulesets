rule TTP_XOR_WriteProcessMemory_6a8b {
  strings:
    $key_6a8b = { 3d f9 [2] 0f db [2] 09 ee [2] 27 ee [2] 18 f2 }

  condition:
    any of them
}