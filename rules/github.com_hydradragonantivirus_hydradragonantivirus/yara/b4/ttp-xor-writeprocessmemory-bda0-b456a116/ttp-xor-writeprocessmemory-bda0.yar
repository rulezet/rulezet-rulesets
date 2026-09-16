rule TTP_XOR_WriteProcessMemory_bda0 {
  strings:
    $key_bda0 = { ea d2 [2] d8 f0 [2] de c5 [2] f0 c5 [2] cf d9 }

  condition:
    any of them
}