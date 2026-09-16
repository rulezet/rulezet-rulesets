rule TTP_XOR_WriteProcessMemory_b516 {
  strings:
    $key_b516 = { e2 64 [2] d0 46 [2] d6 73 [2] f8 73 [2] c7 6f }

  condition:
    any of them
}