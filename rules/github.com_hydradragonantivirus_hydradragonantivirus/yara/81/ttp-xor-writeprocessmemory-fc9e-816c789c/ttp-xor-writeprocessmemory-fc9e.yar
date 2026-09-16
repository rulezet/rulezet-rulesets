rule TTP_XOR_WriteProcessMemory_fc9e {
  strings:
    $key_fc9e = { ab ec [2] 99 ce [2] 9f fb [2] b1 fb [2] 8e e7 }

  condition:
    any of them
}