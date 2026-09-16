rule TTP_XOR_WriteProcessMemory_a5a9 {
  strings:
    $key_a5a9 = { f2 db [2] c0 f9 [2] c6 cc [2] e8 cc [2] d7 d0 }

  condition:
    any of them
}