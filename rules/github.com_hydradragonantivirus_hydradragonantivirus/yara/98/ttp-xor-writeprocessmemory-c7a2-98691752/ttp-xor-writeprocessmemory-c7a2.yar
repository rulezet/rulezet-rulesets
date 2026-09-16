rule TTP_XOR_WriteProcessMemory_c7a2 {
  strings:
    $key_c7a2 = { 90 d0 [2] a2 f2 [2] a4 c7 [2] 8a c7 [2] b5 db }

  condition:
    any of them
}