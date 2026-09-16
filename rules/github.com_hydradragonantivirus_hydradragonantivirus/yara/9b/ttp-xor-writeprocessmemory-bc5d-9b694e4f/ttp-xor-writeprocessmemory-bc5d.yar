rule TTP_XOR_WriteProcessMemory_bc5d {
  strings:
    $key_bc5d = { eb 2f [2] d9 0d [2] df 38 [2] f1 38 [2] ce 24 }

  condition:
    any of them
}