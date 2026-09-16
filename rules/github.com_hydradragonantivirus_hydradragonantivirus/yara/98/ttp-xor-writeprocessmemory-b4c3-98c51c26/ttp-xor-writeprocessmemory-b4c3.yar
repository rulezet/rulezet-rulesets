rule TTP_XOR_WriteProcessMemory_b4c3 {
  strings:
    $key_b4c3 = { e3 b1 [2] d1 93 [2] d7 a6 [2] f9 a6 [2] c6 ba }

  condition:
    any of them
}