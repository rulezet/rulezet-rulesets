rule TTP_XOR_WriteProcessMemory_c78b {
  strings:
    $key_c78b = { 90 f9 [2] a2 db [2] a4 ee [2] 8a ee [2] b5 f2 }

  condition:
    any of them
}