rule TTP_XOR_WriteProcessMemory_0e9c {
  strings:
    $key_0e9c = { 59 ee [2] 6b cc [2] 6d f9 [2] 43 f9 [2] 7c e5 }

  condition:
    any of them
}