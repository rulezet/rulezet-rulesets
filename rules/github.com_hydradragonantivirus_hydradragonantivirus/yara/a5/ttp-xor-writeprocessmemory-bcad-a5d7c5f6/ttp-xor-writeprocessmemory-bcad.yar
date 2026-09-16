rule TTP_XOR_WriteProcessMemory_bcad {
  strings:
    $key_bcad = { eb df [2] d9 fd [2] df c8 [2] f1 c8 [2] ce d4 }

  condition:
    any of them
}