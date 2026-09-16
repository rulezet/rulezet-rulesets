rule TTP_XOR_WriteProcessMemory_b4c1 {
  strings:
    $key_b4c1 = { e3 b3 [2] d1 91 [2] d7 a4 [2] f9 a4 [2] c6 b8 }

  condition:
    any of them
}