rule TTP_XOR_WriteProcessMemory_98ab {
  strings:
    $key_98ab = { cf d9 [2] fd fb [2] fb ce [2] d5 ce [2] ea d2 }

  condition:
    any of them
}