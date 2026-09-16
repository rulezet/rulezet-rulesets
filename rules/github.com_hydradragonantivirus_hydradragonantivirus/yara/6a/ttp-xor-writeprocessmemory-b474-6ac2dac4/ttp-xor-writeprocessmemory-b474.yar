rule TTP_XOR_WriteProcessMemory_b474 {
  strings:
    $key_b474 = { e3 06 [2] d1 24 [2] d7 11 [2] f9 11 [2] c6 0d }

  condition:
    any of them
}