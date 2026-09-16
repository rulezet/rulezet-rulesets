rule TTP_XOR_WriteProcessMemory_bc6c {
  strings:
    $key_bc6c = { eb 1e [2] d9 3c [2] df 09 [2] f1 09 [2] ce 15 }

  condition:
    any of them
}