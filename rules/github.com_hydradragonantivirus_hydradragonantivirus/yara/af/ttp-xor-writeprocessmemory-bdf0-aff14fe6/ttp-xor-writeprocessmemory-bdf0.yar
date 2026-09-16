rule TTP_XOR_WriteProcessMemory_bdf0 {
  strings:
    $key_bdf0 = { ea 82 [2] d8 a0 [2] de 95 [2] f0 95 [2] cf 89 }

  condition:
    any of them
}