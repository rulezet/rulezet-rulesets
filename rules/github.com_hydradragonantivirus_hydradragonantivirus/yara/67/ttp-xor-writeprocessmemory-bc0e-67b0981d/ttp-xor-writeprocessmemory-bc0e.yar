rule TTP_XOR_WriteProcessMemory_bc0e {
  strings:
    $key_bc0e = { eb 7c [2] d9 5e [2] df 6b [2] f1 6b [2] ce 77 }

  condition:
    any of them
}