rule TTP_XOR_WriteProcessMemory_e898 {
  strings:
    $key_e898 = { bf ea [2] 8d c8 [2] 8b fd [2] a5 fd [2] 9a e1 }

  condition:
    any of them
}