rule TTP_XOR_WriteProcessMemory_bc39 {
  strings:
    $key_bc39 = { eb 4b [2] d9 69 [2] df 5c [2] f1 5c [2] ce 40 }

  condition:
    any of them
}