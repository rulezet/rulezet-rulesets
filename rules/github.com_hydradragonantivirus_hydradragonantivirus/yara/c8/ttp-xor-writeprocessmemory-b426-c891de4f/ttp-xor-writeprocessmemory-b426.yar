rule TTP_XOR_WriteProcessMemory_b426 {
  strings:
    $key_b426 = { e3 54 [2] d1 76 [2] d7 43 [2] f9 43 [2] c6 5f }

  condition:
    any of them
}