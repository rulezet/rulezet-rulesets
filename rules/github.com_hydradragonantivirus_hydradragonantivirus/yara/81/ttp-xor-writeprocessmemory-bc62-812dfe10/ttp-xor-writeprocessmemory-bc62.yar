rule TTP_XOR_WriteProcessMemory_bc62 {
  strings:
    $key_bc62 = { eb 10 [2] d9 32 [2] df 07 [2] f1 07 [2] ce 1b }

  condition:
    any of them
}