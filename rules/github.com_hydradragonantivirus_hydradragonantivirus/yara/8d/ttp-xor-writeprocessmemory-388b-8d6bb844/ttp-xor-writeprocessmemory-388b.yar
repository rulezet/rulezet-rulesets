rule TTP_XOR_WriteProcessMemory_388b {
  strings:
    $key_388b = { 6f f9 [2] 5d db [2] 5b ee [2] 75 ee [2] 4a f2 }

  condition:
    any of them
}