rule TTP_XOR_WriteProcessMemory_6e9c {
  strings:
    $key_6e9c = { 39 ee [2] 0b cc [2] 0d f9 [2] 23 f9 [2] 1c e5 }

  condition:
    any of them
}