rule TTP_XOR_WriteProcessMemory_8fd9 {
  strings:
    $key_8fd9 = { d8 ab [2] ea 89 [2] ec bc [2] c2 bc [2] fd a0 }

  condition:
    any of them
}