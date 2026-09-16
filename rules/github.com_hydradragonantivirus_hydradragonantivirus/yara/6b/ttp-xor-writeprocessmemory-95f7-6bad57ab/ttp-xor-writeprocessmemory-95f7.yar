rule TTP_XOR_WriteProcessMemory_95f7 {
  strings:
    $key_95f7 = { c2 85 [2] f0 a7 [2] f6 92 [2] d8 92 [2] e7 8e }

  condition:
    any of them
}