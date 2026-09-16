rule TTP_XOR_WriteProcessMemory_bc09 {
  strings:
    $key_bc09 = { eb 7b [2] d9 59 [2] df 6c [2] f1 6c [2] ce 70 }

  condition:
    any of them
}