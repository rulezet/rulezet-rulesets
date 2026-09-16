rule TTP_XOR_WriteProcessMemory_bc63 {
  strings:
    $key_bc63 = { eb 11 [2] d9 33 [2] df 06 [2] f1 06 [2] ce 1a }

  condition:
    any of them
}