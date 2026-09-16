rule TTP_XOR_WriteProcessMemory_bc90 {
  strings:
    $key_bc90 = { eb e2 [2] d9 c0 [2] df f5 [2] f1 f5 [2] ce e9 }

  condition:
    any of them
}