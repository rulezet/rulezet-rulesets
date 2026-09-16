rule TTP_XOR_WriteProcessMemory_b452 {
  strings:
    $key_b452 = { e3 20 [2] d1 02 [2] d7 37 [2] f9 37 [2] c6 2b }

  condition:
    any of them
}