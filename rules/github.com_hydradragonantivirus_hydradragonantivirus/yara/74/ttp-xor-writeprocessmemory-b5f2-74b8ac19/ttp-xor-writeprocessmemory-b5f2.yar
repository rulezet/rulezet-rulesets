rule TTP_XOR_WriteProcessMemory_b5f2 {
  strings:
    $key_b5f2 = { e2 80 [2] d0 a2 [2] d6 97 [2] f8 97 [2] c7 8b }

  condition:
    any of them
}