rule TTP_XOR_WriteProcessMemory_bc27 {
  strings:
    $key_bc27 = { eb 55 [2] d9 77 [2] df 42 [2] f1 42 [2] ce 5e }

  condition:
    any of them
}