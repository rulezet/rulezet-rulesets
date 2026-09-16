rule TTP_XOR_WriteProcessMemory_bc79 {
  strings:
    $key_bc79 = { eb 0b [2] d9 29 [2] df 1c [2] f1 1c [2] ce 00 }

  condition:
    any of them
}