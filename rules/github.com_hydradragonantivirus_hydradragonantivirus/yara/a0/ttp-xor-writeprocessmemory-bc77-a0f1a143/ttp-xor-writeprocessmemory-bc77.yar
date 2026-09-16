rule TTP_XOR_WriteProcessMemory_bc77 {
  strings:
    $key_bc77 = { eb 05 [2] d9 27 [2] df 12 [2] f1 12 [2] ce 0e }

  condition:
    any of them
}