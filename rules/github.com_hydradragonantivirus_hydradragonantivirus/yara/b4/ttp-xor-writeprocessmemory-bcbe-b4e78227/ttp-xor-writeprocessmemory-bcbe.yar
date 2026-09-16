rule TTP_XOR_WriteProcessMemory_bcbe {
  strings:
    $key_bcbe = { eb cc [2] d9 ee [2] df db [2] f1 db [2] ce c7 }

  condition:
    any of them
}