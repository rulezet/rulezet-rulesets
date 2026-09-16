rule TTP_XOR_WriteProcessMemory_b432 {
  strings:
    $key_b432 = { e3 40 [2] d1 62 [2] d7 57 [2] f9 57 [2] c6 4b }

  condition:
    any of them
}