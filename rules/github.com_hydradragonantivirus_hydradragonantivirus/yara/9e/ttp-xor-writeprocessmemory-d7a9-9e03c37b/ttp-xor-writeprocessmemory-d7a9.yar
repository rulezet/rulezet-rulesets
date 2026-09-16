rule TTP_XOR_WriteProcessMemory_d7a9 {
  strings:
    $key_d7a9 = { 80 db [2] b2 f9 [2] b4 cc [2] 9a cc [2] a5 d0 }

  condition:
    any of them
}