rule TTP_XOR_WriteProcessMemory_b410 {
  strings:
    $key_b410 = { e3 62 [2] d1 40 [2] d7 75 [2] f9 75 [2] c6 69 }

  condition:
    any of them
}