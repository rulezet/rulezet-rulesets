rule TTP_XOR_WriteProcessMemory_d1a2 {
  strings:
    $key_d1a2 = { 86 d0 [2] b4 f2 [2] b2 c7 [2] 9c c7 [2] a3 db }

  condition:
    any of them
}