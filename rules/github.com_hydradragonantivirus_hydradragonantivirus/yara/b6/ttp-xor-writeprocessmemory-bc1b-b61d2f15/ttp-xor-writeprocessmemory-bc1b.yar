rule TTP_XOR_WriteProcessMemory_bc1b {
  strings:
    $key_bc1b = { eb 69 [2] d9 4b [2] df 7e [2] f1 7e [2] ce 62 }

  condition:
    any of them
}