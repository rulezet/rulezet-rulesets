rule TTP_XOR_WriteProcessMemory_b4d1 {
  strings:
    $key_b4d1 = { e3 a3 [2] d1 81 [2] d7 b4 [2] f9 b4 [2] c6 a8 }

  condition:
    any of them
}