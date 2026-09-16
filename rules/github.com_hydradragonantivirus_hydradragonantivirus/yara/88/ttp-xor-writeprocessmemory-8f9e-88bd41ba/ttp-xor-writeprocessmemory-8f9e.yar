rule TTP_XOR_WriteProcessMemory_8f9e {
  strings:
    $key_8f9e = { d8 ec [2] ea ce [2] ec fb [2] c2 fb [2] fd e7 }

  condition:
    any of them
}