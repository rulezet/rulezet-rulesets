rule TTP_XOR_WriteProcessMemory_bdc0 {
  strings:
    $key_bdc0 = { ea b2 [2] d8 90 [2] de a5 [2] f0 a5 [2] cf b9 }

  condition:
    any of them
}