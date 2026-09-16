rule TTP_XOR_WriteProcessMemory_bc56 {
  strings:
    $key_bc56 = { eb 24 [2] d9 06 [2] df 33 [2] f1 33 [2] ce 2f }

  condition:
    any of them
}