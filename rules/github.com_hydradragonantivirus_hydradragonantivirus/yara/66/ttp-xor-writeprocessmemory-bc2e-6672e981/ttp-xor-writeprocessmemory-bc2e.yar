rule TTP_XOR_WriteProcessMemory_bc2e {
  strings:
    $key_bc2e = { eb 5c [2] d9 7e [2] df 4b [2] f1 4b [2] ce 57 }

  condition:
    any of them
}