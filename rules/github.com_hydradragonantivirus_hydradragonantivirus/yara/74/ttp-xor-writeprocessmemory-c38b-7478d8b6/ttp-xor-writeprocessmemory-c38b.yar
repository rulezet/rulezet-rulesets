rule TTP_XOR_WriteProcessMemory_c38b {
  strings:
    $key_c38b = { 94 f9 [2] a6 db [2] a0 ee [2] 8e ee [2] b1 f2 }

  condition:
    any of them
}