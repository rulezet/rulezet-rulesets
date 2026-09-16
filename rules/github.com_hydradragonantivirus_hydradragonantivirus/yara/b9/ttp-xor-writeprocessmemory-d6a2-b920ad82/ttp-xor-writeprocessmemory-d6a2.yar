rule TTP_XOR_WriteProcessMemory_d6a2 {
  strings:
    $key_d6a2 = { 81 d0 [2] b3 f2 [2] b5 c7 [2] 9b c7 [2] a4 db }

  condition:
    any of them
}