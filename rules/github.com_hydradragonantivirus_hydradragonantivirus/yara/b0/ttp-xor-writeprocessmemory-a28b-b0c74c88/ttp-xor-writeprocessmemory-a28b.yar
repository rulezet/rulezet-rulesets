rule TTP_XOR_WriteProcessMemory_a28b {
  strings:
    $key_a28b = { f5 f9 [2] c7 db [2] c1 ee [2] ef ee [2] d0 f2 }

  condition:
    any of them
}