rule TTP_XOR_WriteProcessMemory_8f80 {
  strings:
    $key_8f80 = { d8 f2 [2] ea d0 [2] ec e5 [2] c2 e5 [2] fd f9 }

  condition:
    any of them
}