rule TTP_XOR_WriteProcessMemory_b443 {
  strings:
    $key_b443 = { e3 31 [2] d1 13 [2] d7 26 [2] f9 26 [2] c6 3a }

  condition:
    any of them
}