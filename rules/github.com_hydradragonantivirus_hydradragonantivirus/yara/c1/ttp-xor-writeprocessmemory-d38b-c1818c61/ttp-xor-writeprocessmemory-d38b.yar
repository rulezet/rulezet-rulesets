rule TTP_XOR_WriteProcessMemory_d38b {
  strings:
    $key_d38b = { 84 f9 [2] b6 db [2] b0 ee [2] 9e ee [2] a1 f2 }

  condition:
    any of them
}