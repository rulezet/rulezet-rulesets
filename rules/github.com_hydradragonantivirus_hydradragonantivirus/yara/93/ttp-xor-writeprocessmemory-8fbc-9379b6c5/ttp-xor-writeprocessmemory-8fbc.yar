rule TTP_XOR_WriteProcessMemory_8fbc {
  strings:
    $key_8fbc = { d8 ce [2] ea ec [2] ec d9 [2] c2 d9 [2] fd c5 }

  condition:
    any of them
}