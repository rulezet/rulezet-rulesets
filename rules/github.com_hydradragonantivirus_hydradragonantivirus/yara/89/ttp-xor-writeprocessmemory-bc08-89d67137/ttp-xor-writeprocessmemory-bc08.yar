rule TTP_XOR_WriteProcessMemory_bc08 {
  strings:
    $key_bc08 = { eb 7a [2] d9 58 [2] df 6d [2] f1 6d [2] ce 71 }

  condition:
    any of them
}