rule TTP_XOR_WriteProcessMemory_bc8b {
  strings:
    $key_bc8b = { eb f9 [2] d9 db [2] df ee [2] f1 ee [2] ce f2 }

  condition:
    any of them
}