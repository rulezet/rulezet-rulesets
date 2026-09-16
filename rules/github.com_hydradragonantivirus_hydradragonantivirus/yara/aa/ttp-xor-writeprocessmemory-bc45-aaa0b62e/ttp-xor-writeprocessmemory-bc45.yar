rule TTP_XOR_WriteProcessMemory_bc45 {
  strings:
    $key_bc45 = { eb 37 [2] d9 15 [2] df 20 [2] f1 20 [2] ce 3c }

  condition:
    any of them
}