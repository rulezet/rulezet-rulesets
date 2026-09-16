rule TTP_XOR_WriteProcessMemory_7e9c {
  strings:
    $key_7e9c = { 29 ee [2] 1b cc [2] 1d f9 [2] 33 f9 [2] 0c e5 }

  condition:
    any of them
}