rule TTP_XOR_WriteProcessMemory_bc4c {
  strings:
    $key_bc4c = { eb 3e [2] d9 1c [2] df 29 [2] f1 29 [2] ce 35 }

  condition:
    any of them
}