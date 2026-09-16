rule TTP_XOR_WriteProcessMemory_bc07 {
  strings:
    $key_bc07 = { eb 75 [2] d9 57 [2] df 62 [2] f1 62 [2] ce 7e }

  condition:
    any of them
}