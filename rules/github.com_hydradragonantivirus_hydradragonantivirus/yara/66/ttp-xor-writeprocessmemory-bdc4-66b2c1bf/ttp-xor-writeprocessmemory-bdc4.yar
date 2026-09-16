rule TTP_XOR_WriteProcessMemory_bdc4 {
  strings:
    $key_bdc4 = { ea b6 [2] d8 94 [2] de a1 [2] f0 a1 [2] cf bd }

  condition:
    any of them
}