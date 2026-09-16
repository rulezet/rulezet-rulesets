rule TTP_XOR_WriteProcessMemory_bc03 {
  strings:
    $key_bc03 = { eb 71 [2] d9 53 [2] df 66 [2] f1 66 [2] ce 7a }

  condition:
    any of them
}