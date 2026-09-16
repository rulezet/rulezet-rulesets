rule TTP_XOR_WriteProcessMemory_bc34 {
  strings:
    $key_bc34 = { eb 46 [2] d9 64 [2] df 51 [2] f1 51 [2] ce 4d }

  condition:
    any of them
}