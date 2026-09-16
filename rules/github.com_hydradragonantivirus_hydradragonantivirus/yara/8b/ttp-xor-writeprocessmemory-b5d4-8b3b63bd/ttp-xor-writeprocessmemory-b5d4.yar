rule TTP_XOR_WriteProcessMemory_b5d4 {
  strings:
    $key_b5d4 = { e2 a6 [2] d0 84 [2] d6 b1 [2] f8 b1 [2] c7 ad }

  condition:
    any of them
}