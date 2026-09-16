rule TTP_XOR_WriteProcessMemory_bc9c {
  strings:
    $key_bc9c = { eb ee [2] d9 cc [2] df f9 [2] f1 f9 [2] ce e5 }

  condition:
    any of them
}