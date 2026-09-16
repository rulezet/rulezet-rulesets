rule TTP_XOR_WriteProcessMemory_8f92 {
  strings:
    $key_8f92 = { d8 e0 [2] ea c2 [2] ec f7 [2] c2 f7 [2] fd eb }

  condition:
    any of them
}