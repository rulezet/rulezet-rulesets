rule TTP_XOR_WriteProcessMemory_98db {
  strings:
    $key_98db = { cf a9 [2] fd 8b [2] fb be [2] d5 be [2] ea a2 }

  condition:
    any of them
}