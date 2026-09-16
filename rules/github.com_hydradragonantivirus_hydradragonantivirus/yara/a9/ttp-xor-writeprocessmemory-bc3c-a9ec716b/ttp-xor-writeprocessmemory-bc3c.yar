rule TTP_XOR_WriteProcessMemory_bc3c {
  strings:
    $key_bc3c = { eb 4e [2] d9 6c [2] df 59 [2] f1 59 [2] ce 45 }

  condition:
    any of them
}