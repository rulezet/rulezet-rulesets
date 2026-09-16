rule TTP_XOR_WriteProcessMemory_bc44 {
  strings:
    $key_bc44 = { eb 36 [2] d9 14 [2] df 21 [2] f1 21 [2] ce 3d }

  condition:
    any of them
}