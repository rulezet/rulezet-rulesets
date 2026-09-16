rule TTP_XOR_WriteProcessMemory_bc8a {
  strings:
    $key_bc8a = { eb f8 [2] d9 da [2] df ef [2] f1 ef [2] ce f3 }

  condition:
    any of them
}