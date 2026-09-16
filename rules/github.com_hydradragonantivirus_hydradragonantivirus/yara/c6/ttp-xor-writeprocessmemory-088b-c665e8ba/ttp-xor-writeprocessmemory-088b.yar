rule TTP_XOR_WriteProcessMemory_088b {
  strings:
    $key_088b = { 5f f9 [2] 6d db [2] 6b ee [2] 45 ee [2] 7a f2 }

  condition:
    any of them
}