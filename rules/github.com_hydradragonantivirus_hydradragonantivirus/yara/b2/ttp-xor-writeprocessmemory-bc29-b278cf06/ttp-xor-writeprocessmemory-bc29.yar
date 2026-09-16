rule TTP_XOR_WriteProcessMemory_bc29 {
  strings:
    $key_bc29 = { eb 5b [2] d9 79 [2] df 4c [2] f1 4c [2] ce 50 }

  condition:
    any of them
}