rule TTP_XOR_WriteProcessMemory_8fa4 {
  strings:
    $key_8fa4 = { d8 d6 [2] ea f4 [2] ec c1 [2] c2 c1 [2] fd dd }

  condition:
    any of them
}