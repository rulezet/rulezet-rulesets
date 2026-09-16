rule TTP_XOR_WriteProcessMemory_8f98 {
  strings:
    $key_8f98 = { d8 ea [2] ea c8 [2] ec fd [2] c2 fd [2] fd e1 }

  condition:
    any of them
}