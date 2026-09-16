rule TTP_XOR_WriteProcessMemory_d4a2 {
  strings:
    $key_d4a2 = { 83 d0 [2] b1 f2 [2] b7 c7 [2] 99 c7 [2] a6 db }

  condition:
    any of them
}