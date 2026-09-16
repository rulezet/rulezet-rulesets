rule TTP_XOR_WriteProcessMemory_b5f3 {
  strings:
    $key_b5f3 = { e2 81 [2] d0 a3 [2] d6 96 [2] f8 96 [2] c7 8a }

  condition:
    any of them
}