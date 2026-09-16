rule TTP_XOR_WriteProcessMemory_bc81 {
  strings:
    $key_bc81 = { eb f3 [2] d9 d1 [2] df e4 [2] f1 e4 [2] ce f8 }

  condition:
    any of them
}