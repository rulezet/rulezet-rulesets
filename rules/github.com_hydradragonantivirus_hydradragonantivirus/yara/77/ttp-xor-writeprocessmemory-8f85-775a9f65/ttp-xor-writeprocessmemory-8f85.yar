rule TTP_XOR_WriteProcessMemory_8f85 {
  strings:
    $key_8f85 = { d8 f7 [2] ea d5 [2] ec e0 [2] c2 e0 [2] fd fc }

  condition:
    any of them
}