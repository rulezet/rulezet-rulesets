rule TTP_XOR_WriteProcessMemory_a2a9 {
  strings:
    $key_a2a9 = { f5 db [2] c7 f9 [2] c1 cc [2] ef cc [2] d0 d0 }

  condition:
    any of them
}