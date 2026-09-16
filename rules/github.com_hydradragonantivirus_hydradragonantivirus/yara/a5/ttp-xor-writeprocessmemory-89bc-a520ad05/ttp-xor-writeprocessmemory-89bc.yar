rule TTP_XOR_WriteProcessMemory_89bc {
  strings:
    $key_89bc = { de ce [2] ec ec [2] ea d9 [2] c4 d9 [2] fb c5 }

  condition:
    any of them
}