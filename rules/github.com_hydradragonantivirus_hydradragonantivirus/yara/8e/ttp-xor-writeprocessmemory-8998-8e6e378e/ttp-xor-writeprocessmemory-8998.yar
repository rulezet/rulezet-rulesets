rule TTP_XOR_WriteProcessMemory_8998 {
  strings:
    $key_8998 = { de ea [2] ec c8 [2] ea fd [2] c4 fd [2] fb e1 }

  condition:
    any of them
}