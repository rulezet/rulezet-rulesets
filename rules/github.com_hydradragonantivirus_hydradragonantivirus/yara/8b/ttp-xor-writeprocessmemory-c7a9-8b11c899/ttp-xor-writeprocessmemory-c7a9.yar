rule TTP_XOR_WriteProcessMemory_c7a9 {
  strings:
    $key_c7a9 = { 90 db [2] a2 f9 [2] a4 cc [2] 8a cc [2] b5 d0 }

  condition:
    any of them
}