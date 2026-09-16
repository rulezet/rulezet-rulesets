rule TTP_XOR_WriteProcessMemory_8fcb {
  strings:
    $key_8fcb = { d8 b9 [2] ea 9b [2] ec ae [2] c2 ae [2] fd b2 }

  condition:
    any of them
}