rule TTP_XOR_WriteProcessMemory_e58b {
  strings:
    $key_e58b = { b2 f9 [2] 80 db [2] 86 ee [2] a8 ee [2] 97 f2 }

  condition:
    any of them
}