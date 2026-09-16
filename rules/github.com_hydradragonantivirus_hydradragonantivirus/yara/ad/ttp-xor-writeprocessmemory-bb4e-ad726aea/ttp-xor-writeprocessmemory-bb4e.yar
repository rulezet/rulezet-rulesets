rule TTP_XOR_WriteProcessMemory_bb4e {
  strings:
    $key_bb4e = { ec 3c [2] de 1e [2] d8 2b [2] f6 2b [2] c9 37 }

  condition:
    any of them
}