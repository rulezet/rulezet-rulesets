rule TTP_XOR_WriteProcessMemory_bc22 {
  strings:
    $key_bc22 = { eb 50 [2] d9 72 [2] df 47 [2] f1 47 [2] ce 5b }

  condition:
    any of them
}