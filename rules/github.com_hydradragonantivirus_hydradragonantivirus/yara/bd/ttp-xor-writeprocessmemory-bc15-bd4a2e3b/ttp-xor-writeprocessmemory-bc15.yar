rule TTP_XOR_WriteProcessMemory_bc15 {
  strings:
    $key_bc15 = { eb 67 [2] d9 45 [2] df 70 [2] f1 70 [2] ce 6c }

  condition:
    any of them
}