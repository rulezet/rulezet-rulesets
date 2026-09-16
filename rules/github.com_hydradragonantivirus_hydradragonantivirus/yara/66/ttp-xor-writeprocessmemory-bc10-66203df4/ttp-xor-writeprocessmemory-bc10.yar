rule TTP_XOR_WriteProcessMemory_bc10 {
  strings:
    $key_bc10 = { eb 62 [2] d9 40 [2] df 75 [2] f1 75 [2] ce 69 }

  condition:
    any of them
}