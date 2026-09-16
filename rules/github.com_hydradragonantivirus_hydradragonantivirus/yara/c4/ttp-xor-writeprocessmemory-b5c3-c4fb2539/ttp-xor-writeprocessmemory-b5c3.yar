rule TTP_XOR_WriteProcessMemory_b5c3 {
  strings:
    $key_b5c3 = { e2 b1 [2] d0 93 [2] d6 a6 [2] f8 a6 [2] c7 ba }

  condition:
    any of them
}