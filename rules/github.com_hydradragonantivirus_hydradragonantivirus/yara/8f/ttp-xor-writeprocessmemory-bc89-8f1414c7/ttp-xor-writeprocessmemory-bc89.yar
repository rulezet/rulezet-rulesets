rule TTP_XOR_WriteProcessMemory_bc89 {
  strings:
    $key_bc89 = { eb fb [2] d9 d9 [2] df ec [2] f1 ec [2] ce f0 }

  condition:
    any of them
}