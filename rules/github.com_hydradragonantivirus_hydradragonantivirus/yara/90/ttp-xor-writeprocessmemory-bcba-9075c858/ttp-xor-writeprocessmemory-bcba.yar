rule TTP_XOR_WriteProcessMemory_bcba {
  strings:
    $key_bcba = { eb c8 [2] d9 ea [2] df df [2] f1 df [2] ce c3 }

  condition:
    any of them
}