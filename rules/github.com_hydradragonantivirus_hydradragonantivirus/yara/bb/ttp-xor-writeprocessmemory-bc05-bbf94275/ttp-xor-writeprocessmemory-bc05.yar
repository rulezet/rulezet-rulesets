rule TTP_XOR_WriteProcessMemory_bc05 {
  strings:
    $key_bc05 = { eb 77 [2] d9 55 [2] df 60 [2] f1 60 [2] ce 7c }

  condition:
    any of them
}