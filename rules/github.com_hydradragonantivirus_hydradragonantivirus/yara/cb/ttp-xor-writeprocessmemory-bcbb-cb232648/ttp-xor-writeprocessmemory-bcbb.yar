rule TTP_XOR_WriteProcessMemory_bcbb {
  strings:
    $key_bcbb = { eb c9 [2] d9 eb [2] df de [2] f1 de [2] ce c2 }

  condition:
    any of them
}