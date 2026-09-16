rule TTP_XOR_WriteProcessMemory_3e8b {
  strings:
    $key_3e8b = { 69 f9 [2] 5b db [2] 5d ee [2] 73 ee [2] 4c f2 }

  condition:
    any of them
}