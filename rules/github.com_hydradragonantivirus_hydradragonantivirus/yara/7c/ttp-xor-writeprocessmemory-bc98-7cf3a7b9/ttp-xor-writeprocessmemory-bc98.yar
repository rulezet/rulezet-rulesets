rule TTP_XOR_WriteProcessMemory_bc98 {
  strings:
    $key_bc98 = { eb ea [2] d9 c8 [2] df fd [2] f1 fd [2] ce e1 }

  condition:
    any of them
}