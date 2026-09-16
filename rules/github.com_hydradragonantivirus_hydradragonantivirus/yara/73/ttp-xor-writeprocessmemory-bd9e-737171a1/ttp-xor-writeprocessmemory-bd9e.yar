rule TTP_XOR_WriteProcessMemory_bd9e {
  strings:
    $key_bd9e = { ea ec [2] d8 ce [2] de fb [2] f0 fb [2] cf e7 }

  condition:
    any of them
}