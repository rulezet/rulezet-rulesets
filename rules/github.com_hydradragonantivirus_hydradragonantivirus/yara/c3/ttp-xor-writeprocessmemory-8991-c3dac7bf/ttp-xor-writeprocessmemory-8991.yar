rule TTP_XOR_WriteProcessMemory_8991 {
  strings:
    $key_8991 = { de e3 [2] ec c1 [2] ea f4 [2] c4 f4 [2] fb e8 }

  condition:
    any of them
}