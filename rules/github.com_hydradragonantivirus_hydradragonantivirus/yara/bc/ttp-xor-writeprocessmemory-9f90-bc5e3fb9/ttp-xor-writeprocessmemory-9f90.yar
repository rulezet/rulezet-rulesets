rule TTP_XOR_WriteProcessMemory_9f90 {
  strings:
    $key_9f90 = { c8 e2 [2] fa c0 [2] fc f5 [2] d2 f5 [2] ed e9 }

  condition:
    any of them
}