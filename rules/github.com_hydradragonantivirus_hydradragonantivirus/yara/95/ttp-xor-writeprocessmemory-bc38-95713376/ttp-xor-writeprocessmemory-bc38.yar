rule TTP_XOR_WriteProcessMemory_bc38 {
  strings:
    $key_bc38 = { eb 4a [2] d9 68 [2] df 5d [2] f1 5d [2] ce 41 }

  condition:
    any of them
}