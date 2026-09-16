rule TTP_XOR_WriteProcessMemory_95b9 {
  strings:
    $key_95b9 = { c2 cb [2] f0 e9 [2] f6 dc [2] d8 dc [2] e7 c0 }

  condition:
    any of them
}