rule TTP_XOR_WriteProcessMemory_bda4 {
  strings:
    $key_bda4 = { ea d6 [2] d8 f4 [2] de c1 [2] f0 c1 [2] cf dd }

  condition:
    any of them
}