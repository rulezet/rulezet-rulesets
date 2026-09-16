rule TTP_XOR_WriteProcessMemory_b576 {
  strings:
    $key_b576 = { e2 04 [2] d0 26 [2] d6 13 [2] f8 13 [2] c7 0f }

  condition:
    any of them
}