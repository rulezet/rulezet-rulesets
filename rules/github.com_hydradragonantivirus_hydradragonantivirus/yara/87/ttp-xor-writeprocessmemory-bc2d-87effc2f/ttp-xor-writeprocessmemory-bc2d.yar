rule TTP_XOR_WriteProcessMemory_bc2d {
  strings:
    $key_bc2d = { eb 5f [2] d9 7d [2] df 48 [2] f1 48 [2] ce 54 }

  condition:
    any of them
}