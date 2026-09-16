rule TTP_XOR_WriteProcessMemory_95f3 {
  strings:
    $key_95f3 = { c2 81 [2] f0 a3 [2] f6 96 [2] d8 96 [2] e7 8a }

  condition:
    any of them
}