rule TTP_XOR_WriteProcessMemory_bc6d {
  strings:
    $key_bc6d = { eb 1f [2] d9 3d [2] df 08 [2] f1 08 [2] ce 14 }

  condition:
    any of them
}