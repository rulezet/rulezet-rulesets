rule TTP_XOR_WriteProcessMemory_8fa3 {
  strings:
    $key_8fa3 = { d8 d1 [2] ea f3 [2] ec c6 [2] c2 c6 [2] fd da }

  condition:
    any of them
}