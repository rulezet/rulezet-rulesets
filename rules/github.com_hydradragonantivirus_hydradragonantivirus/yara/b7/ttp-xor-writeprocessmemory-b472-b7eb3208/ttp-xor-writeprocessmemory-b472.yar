rule TTP_XOR_WriteProcessMemory_b472 {
  strings:
    $key_b472 = { e3 00 [2] d1 22 [2] d7 17 [2] f9 17 [2] c6 0b }

  condition:
    any of them
}