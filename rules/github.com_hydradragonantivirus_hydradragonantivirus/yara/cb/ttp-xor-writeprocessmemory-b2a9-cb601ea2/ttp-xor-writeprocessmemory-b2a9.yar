rule TTP_XOR_WriteProcessMemory_b2a9 {
  strings:
    $key_b2a9 = { e5 db [2] d7 f9 [2] d1 cc [2] ff cc [2] c0 d0 }

  condition:
    any of them
}