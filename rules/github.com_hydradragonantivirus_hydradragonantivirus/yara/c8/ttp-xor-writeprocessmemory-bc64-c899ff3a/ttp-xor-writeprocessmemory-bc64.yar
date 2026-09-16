rule TTP_XOR_WriteProcessMemory_bc64 {
  strings:
    $key_bc64 = { eb 16 [2] d9 34 [2] df 01 [2] f1 01 [2] ce 1d }

  condition:
    any of them
}