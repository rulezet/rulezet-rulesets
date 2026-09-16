rule TTP_XOR_WriteProcessMemory_bc4e {
  strings:
    $key_bc4e = { eb 3c [2] d9 1e [2] df 2b [2] f1 2b [2] ce 37 }

  condition:
    any of them
}