rule TTP_XOR_WriteProcessMemory_acab {
  strings:
    $key_acab = { fb d9 [2] c9 fb [2] cf ce [2] e1 ce [2] de d2 }

  condition:
    any of them
}