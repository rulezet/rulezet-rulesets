rule TTP_XOR_WriteProcessMemory_b4e7 {
  strings:
    $key_b4e7 = { e3 95 [2] d1 b7 [2] d7 82 [2] f9 82 [2] c6 9e }

  condition:
    any of them
}