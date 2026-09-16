rule TTP_XOR_WriteProcessMemory_95a3 {
  strings:
    $key_95a3 = { c2 d1 [2] f0 f3 [2] f6 c6 [2] d8 c6 [2] e7 da }

  condition:
    any of them
}