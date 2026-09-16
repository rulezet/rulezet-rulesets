rule TTP_XOR_WriteProcessMemory_2e8b {
  strings:
    $key_2e8b = { 79 f9 [2] 4b db [2] 4d ee [2] 63 ee [2] 5c f2 }

  condition:
    any of them
}