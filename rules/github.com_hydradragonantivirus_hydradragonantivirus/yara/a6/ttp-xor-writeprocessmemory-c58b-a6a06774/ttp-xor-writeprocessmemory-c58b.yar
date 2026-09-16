rule TTP_XOR_WriteProcessMemory_c58b {
  strings:
    $key_c58b = { 92 f9 [2] a0 db [2] a6 ee [2] 88 ee [2] b7 f2 }

  condition:
    any of them
}