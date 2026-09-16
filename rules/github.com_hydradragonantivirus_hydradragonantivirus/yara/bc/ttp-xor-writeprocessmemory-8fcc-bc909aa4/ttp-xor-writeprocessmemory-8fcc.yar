rule TTP_XOR_WriteProcessMemory_8fcc {
  strings:
    $key_8fcc = { d8 be [2] ea 9c [2] ec a9 [2] c2 a9 [2] fd b5 }

  condition:
    any of them
}