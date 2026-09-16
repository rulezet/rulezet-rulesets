rule TTP_XOR_WriteProcessMemory_a4a9 {
  strings:
    $key_a4a9 = { f3 db [2] c1 f9 [2] c7 cc [2] e9 cc [2] d6 d0 }

  condition:
    any of them
}