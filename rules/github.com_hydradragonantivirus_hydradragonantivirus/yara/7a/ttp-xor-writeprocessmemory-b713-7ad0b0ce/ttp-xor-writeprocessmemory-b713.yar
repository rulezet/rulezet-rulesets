rule TTP_XOR_WriteProcessMemory_b713 {
  strings:
    $key_b713 = { e0 61 [2] d2 43 [2] d4 76 [2] fa 76 [2] c5 6a }

  condition:
    any of them
}