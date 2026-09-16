rule TTP_XOR_WriteProcessMemory_bc02 {
  strings:
    $key_bc02 = { eb 70 [2] d9 52 [2] df 67 [2] f1 67 [2] ce 7b }

  condition:
    any of them
}