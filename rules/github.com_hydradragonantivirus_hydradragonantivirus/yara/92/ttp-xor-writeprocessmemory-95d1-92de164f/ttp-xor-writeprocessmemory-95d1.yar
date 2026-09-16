rule TTP_XOR_WriteProcessMemory_95d1 {
  strings:
    $key_95d1 = { c2 a3 [2] f0 81 [2] f6 b4 [2] d8 b4 [2] e7 a8 }

  condition:
    any of them
}