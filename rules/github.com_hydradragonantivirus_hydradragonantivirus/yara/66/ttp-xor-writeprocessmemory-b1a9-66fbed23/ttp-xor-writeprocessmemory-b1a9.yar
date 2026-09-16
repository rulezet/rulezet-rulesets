rule TTP_XOR_WriteProcessMemory_b1a9 {
  strings:
    $key_b1a9 = { e6 db [2] d4 f9 [2] d2 cc [2] fc cc [2] c3 d0 }

  condition:
    any of them
}