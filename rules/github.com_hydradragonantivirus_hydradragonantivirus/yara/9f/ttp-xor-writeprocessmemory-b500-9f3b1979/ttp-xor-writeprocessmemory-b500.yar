rule TTP_XOR_WriteProcessMemory_b500 {
  strings:
    $key_b500 = { e2 72 [2] d0 50 [2] d6 65 [2] f8 65 [2] c7 79 }

  condition:
    any of them
}