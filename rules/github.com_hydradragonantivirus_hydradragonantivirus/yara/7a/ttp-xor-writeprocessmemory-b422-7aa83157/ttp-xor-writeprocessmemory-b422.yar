rule TTP_XOR_WriteProcessMemory_b422 {
  strings:
    $key_b422 = { e3 50 [2] d1 72 [2] d7 47 [2] f9 47 [2] c6 5b }

  condition:
    any of them
}