rule TTP_XOR_WriteProcessMemory_8f8c {
  strings:
    $key_8f8c = { d8 fe [2] ea dc [2] ec e9 [2] c2 e9 [2] fd f5 }

  condition:
    any of them
}