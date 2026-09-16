rule TTP_XOR_WriteProcessMemory_bc74 {
  strings:
    $key_bc74 = { eb 06 [2] d9 24 [2] df 11 [2] f1 11 [2] ce 0d }

  condition:
    any of them
}