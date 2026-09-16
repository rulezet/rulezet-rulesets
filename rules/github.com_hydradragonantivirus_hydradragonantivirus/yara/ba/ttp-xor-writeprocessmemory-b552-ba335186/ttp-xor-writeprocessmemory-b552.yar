rule TTP_XOR_WriteProcessMemory_b552 {
  strings:
    $key_b552 = { e2 20 [2] d0 02 [2] d6 37 [2] f8 37 [2] c7 2b }

  condition:
    any of them
}