rule TTP_XOR_WriteProcessMemory_a6a9 {
  strings:
    $key_a6a9 = { f1 db [2] c3 f9 [2] c5 cc [2] eb cc [2] d4 d0 }

  condition:
    any of them
}