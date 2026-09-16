rule TTP_XOR_WriteProcessMemory_829e {
  strings:
    $key_829e = { d5 ec [2] e7 ce [2] e1 fb [2] cf fb [2] f0 e7 }

  condition:
    any of them
}