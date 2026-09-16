rule TTP_XOR_WriteProcessMemory_bc3e {
  strings:
    $key_bc3e = { eb 4c [2] d9 6e [2] df 5b [2] f1 5b [2] ce 47 }

  condition:
    any of them
}