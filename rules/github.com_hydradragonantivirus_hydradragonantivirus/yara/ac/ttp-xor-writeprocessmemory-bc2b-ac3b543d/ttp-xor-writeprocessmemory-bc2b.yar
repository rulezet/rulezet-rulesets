rule TTP_XOR_WriteProcessMemory_bc2b {
  strings:
    $key_bc2b = { eb 59 [2] d9 7b [2] df 4e [2] f1 4e [2] ce 52 }

  condition:
    any of them
}