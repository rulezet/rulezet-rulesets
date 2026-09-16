rule TTP_XOR_WriteProcessMemory_8f96 {
  strings:
    $key_8f96 = { d8 e4 [2] ea c6 [2] ec f3 [2] c2 f3 [2] fd ef }

  condition:
    any of them
}