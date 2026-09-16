rule TTP_XOR_WriteProcessMemory_95b3 {
  strings:
    $key_95b3 = { c2 c1 [2] f0 e3 [2] f6 d6 [2] d8 d6 [2] e7 ca }

  condition:
    any of them
}