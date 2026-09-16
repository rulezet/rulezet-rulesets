rule TTP_XOR_WriteProcessMemory_bc1c {
  strings:
    $key_bc1c = { eb 6e [2] d9 4c [2] df 79 [2] f1 79 [2] ce 65 }

  condition:
    any of them
}