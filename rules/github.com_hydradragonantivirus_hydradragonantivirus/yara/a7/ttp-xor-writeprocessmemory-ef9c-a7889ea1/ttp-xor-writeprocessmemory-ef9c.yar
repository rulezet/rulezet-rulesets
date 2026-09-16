rule TTP_XOR_WriteProcessMemory_ef9c {
  strings:
    $key_ef9c = { b8 ee [2] 8a cc [2] 8c f9 [2] a2 f9 [2] 9d e5 }

  condition:
    any of them
}