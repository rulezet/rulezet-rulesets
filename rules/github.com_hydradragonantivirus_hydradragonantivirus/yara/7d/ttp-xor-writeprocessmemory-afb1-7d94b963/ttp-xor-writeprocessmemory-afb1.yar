rule TTP_XOR_WriteProcessMemory_afb1 {
  strings:
    $key_afb1 = { f8 c3 [2] ca e1 [2] cc d4 [2] e2 d4 [2] dd c8 }

  condition:
    any of them
}