rule TTP_XOR_WriteProcessMemory_8f90 {
  strings:
    $key_8f90 = { d8 e2 [2] ea c0 [2] ec f5 [2] c2 f5 [2] fd e9 }

  condition:
    any of them
}