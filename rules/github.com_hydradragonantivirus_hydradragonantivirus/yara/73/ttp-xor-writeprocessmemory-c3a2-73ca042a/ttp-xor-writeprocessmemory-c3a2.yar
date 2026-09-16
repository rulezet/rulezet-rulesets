rule TTP_XOR_WriteProcessMemory_c3a2 {
  strings:
    $key_c3a2 = { 94 d0 [2] a6 f2 [2] a0 c7 [2] 8e c7 [2] b1 db }

  condition:
    any of them
}