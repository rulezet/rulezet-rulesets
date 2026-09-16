rule TTP_XOR_WriteProcessMemory_95d5 {
  strings:
    $key_95d5 = { c2 a7 [2] f0 85 [2] f6 b0 [2] d8 b0 [2] e7 ac }

  condition:
    any of them
}