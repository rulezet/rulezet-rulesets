rule TTP_XOR_WriteProcessMemory_bc95 {
  strings:
    $key_bc95 = { eb e7 [2] d9 c5 [2] df f0 [2] f1 f0 [2] ce ec }

  condition:
    any of them
}