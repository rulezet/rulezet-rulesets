rule TTP_XOR_WriteProcessMemory_a3a9 {
  strings:
    $key_a3a9 = { f4 db [2] c6 f9 [2] c0 cc [2] ee cc [2] d1 d0 }

  condition:
    any of them
}