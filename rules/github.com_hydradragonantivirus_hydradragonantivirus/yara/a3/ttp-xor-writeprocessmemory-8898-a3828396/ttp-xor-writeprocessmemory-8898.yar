rule TTP_XOR_WriteProcessMemory_8898 {
  strings:
    $key_8898 = { df ea [2] ed c8 [2] eb fd [2] c5 fd [2] fa e1 }

  condition:
    any of them
}