rule TTP_XOR_WriteProcessMemory_bc40 {
  strings:
    $key_bc40 = { eb 32 [2] d9 10 [2] df 25 [2] f1 25 [2] ce 39 }

  condition:
    any of them
}