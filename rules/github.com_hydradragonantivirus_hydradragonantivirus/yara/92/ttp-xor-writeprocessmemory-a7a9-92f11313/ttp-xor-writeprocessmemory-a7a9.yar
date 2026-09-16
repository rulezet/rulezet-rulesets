rule TTP_XOR_WriteProcessMemory_a7a9 {
  strings:
    $key_a7a9 = { f0 db [2] c2 f9 [2] c4 cc [2] ea cc [2] d5 d0 }

  condition:
    any of them
}