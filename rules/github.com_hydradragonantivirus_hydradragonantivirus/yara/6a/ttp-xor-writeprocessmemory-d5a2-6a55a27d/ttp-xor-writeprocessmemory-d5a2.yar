rule TTP_XOR_WriteProcessMemory_d5a2 {
  strings:
    $key_d5a2 = { 82 d0 [2] b0 f2 [2] b6 c7 [2] 98 c7 [2] a7 db }

  condition:
    any of them
}