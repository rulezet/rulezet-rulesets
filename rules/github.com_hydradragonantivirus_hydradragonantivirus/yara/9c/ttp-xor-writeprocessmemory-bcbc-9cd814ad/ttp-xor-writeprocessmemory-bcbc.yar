rule TTP_XOR_WriteProcessMemory_bcbc {
  strings:
    $key_bcbc = { eb ce [2] d9 ec [2] df d9 [2] f1 d9 [2] ce c5 }

  condition:
    any of them
}