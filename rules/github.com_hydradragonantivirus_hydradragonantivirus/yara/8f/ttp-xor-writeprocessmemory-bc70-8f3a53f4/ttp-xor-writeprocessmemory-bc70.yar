rule TTP_XOR_WriteProcessMemory_bc70 {
  strings:
    $key_bc70 = { eb 02 [2] d9 20 [2] df 15 [2] f1 15 [2] ce 09 }

  condition:
    any of them
}