rule TTP_XOR_WriteProcessMemory_6f9c {
  strings:
    $key_6f9c = { 38 ee [2] 0a cc [2] 0c f9 [2] 22 f9 [2] 1d e5 }

  condition:
    any of them
}