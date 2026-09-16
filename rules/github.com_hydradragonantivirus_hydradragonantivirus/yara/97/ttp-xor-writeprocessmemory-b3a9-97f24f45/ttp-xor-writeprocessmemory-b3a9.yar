rule TTP_XOR_WriteProcessMemory_b3a9 {
  strings:
    $key_b3a9 = { e4 db [2] d6 f9 [2] d0 cc [2] fe cc [2] c1 d0 }

  condition:
    any of them
}