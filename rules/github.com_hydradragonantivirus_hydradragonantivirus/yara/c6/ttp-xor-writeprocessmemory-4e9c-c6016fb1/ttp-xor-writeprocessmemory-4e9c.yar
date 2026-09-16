rule TTP_XOR_WriteProcessMemory_4e9c {
  strings:
    $key_4e9c = { 19 ee [2] 2b cc [2] 2d f9 [2] 03 f9 [2] 3c e5 }

  condition:
    any of them
}