rule TTP_XOR_WriteProcessMemory_b5a9 {
  strings:
    $key_b5a9 = { e2 db [2] d0 f9 [2] d6 cc [2] f8 cc [2] c7 d0 }

  condition:
    any of them
}