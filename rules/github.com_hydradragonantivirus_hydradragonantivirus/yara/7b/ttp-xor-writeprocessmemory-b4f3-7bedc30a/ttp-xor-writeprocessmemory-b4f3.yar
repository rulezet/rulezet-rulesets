rule TTP_XOR_WriteProcessMemory_b4f3 {
  strings:
    $key_b4f3 = { e3 81 [2] d1 a3 [2] d7 96 [2] f9 96 [2] c6 8a }

  condition:
    any of them
}