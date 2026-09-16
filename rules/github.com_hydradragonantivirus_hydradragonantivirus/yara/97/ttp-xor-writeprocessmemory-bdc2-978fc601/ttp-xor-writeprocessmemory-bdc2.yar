rule TTP_XOR_WriteProcessMemory_bdc2 {
  strings:
    $key_bdc2 = { ea b0 [2] d8 92 [2] de a7 [2] f0 a7 [2] cf bb }

  condition:
    any of them
}