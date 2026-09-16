rule TTP_XOR_WriteProcessMemory_b533 {
  strings:
    $key_b533 = { e2 41 [2] d0 63 [2] d6 56 [2] f8 56 [2] c7 4a }

  condition:
    any of them
}