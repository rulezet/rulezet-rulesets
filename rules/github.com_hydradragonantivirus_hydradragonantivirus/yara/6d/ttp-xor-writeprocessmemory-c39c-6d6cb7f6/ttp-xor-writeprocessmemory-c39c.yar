rule TTP_XOR_WriteProcessMemory_c39c {
  strings:
    $key_c39c = { 94 ee [2] a6 cc [2] a0 f9 [2] 8e f9 [2] b1 e5 }

  condition:
    any of them
}