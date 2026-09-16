rule TTP_XOR_WriteProcessMemory_bc18 {
  strings:
    $key_bc18 = { eb 6a [2] d9 48 [2] df 7d [2] f1 7d [2] ce 61 }

  condition:
    any of them
}