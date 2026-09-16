rule TTP_XOR_WriteProcessMemory_4f9c {
  strings:
    $key_4f9c = { 18 ee [2] 2a cc [2] 2c f9 [2] 02 f9 [2] 3d e5 }

  condition:
    any of them
}