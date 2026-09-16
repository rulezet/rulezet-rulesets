rule TTP_XOR_WriteProcessMemory_3f9c {
  strings:
    $key_3f9c = { 68 ee [2] 5a cc [2] 5c f9 [2] 72 f9 [2] 4d e5 }

  condition:
    any of them
}