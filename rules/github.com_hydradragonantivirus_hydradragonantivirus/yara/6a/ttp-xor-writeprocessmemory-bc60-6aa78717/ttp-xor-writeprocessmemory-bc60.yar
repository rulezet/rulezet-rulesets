rule TTP_XOR_WriteProcessMemory_bc60 {
  strings:
    $key_bc60 = { eb 12 [2] d9 30 [2] df 05 [2] f1 05 [2] ce 19 }

  condition:
    any of them
}