rule TTP_XOR_WriteProcessMemory_bdab {
  strings:
    $key_bdab = { ea d9 [2] d8 fb [2] de ce [2] f0 ce [2] cf d2 }

  condition:
    any of them
}