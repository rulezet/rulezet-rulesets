rule TTP_XOR_WriteProcessMemory_b4e2 {
  strings:
    $key_b4e2 = { e3 90 [2] d1 b2 [2] d7 87 [2] f9 87 [2] c6 9b }

  condition:
    any of them
}