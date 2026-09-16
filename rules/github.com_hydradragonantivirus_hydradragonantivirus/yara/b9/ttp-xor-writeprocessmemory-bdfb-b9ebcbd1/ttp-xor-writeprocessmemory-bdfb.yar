rule TTP_XOR_WriteProcessMemory_bdfb {
  strings:
    $key_bdfb = { ea 89 [2] d8 ab [2] de 9e [2] f0 9e [2] cf 82 }

  condition:
    any of them
}