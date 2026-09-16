rule TTP_XOR_WriteProcessMemory_bc78 {
  strings:
    $key_bc78 = { eb 0a [2] d9 28 [2] df 1d [2] f1 1d [2] ce 01 }

  condition:
    any of them
}