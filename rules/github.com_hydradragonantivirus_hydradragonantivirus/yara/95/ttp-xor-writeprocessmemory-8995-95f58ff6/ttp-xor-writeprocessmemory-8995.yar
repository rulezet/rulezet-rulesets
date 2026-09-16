rule TTP_XOR_WriteProcessMemory_8995 {
  strings:
    $key_8995 = { de e7 [2] ec c5 [2] ea f0 [2] c4 f0 [2] fb ec }

  condition:
    any of them
}