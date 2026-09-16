rule TTP_XOR_WriteProcessMemory_b5e7 {
  strings:
    $key_b5e7 = { e2 95 [2] d0 b7 [2] d6 82 [2] f8 82 [2] c7 9e }

  condition:
    any of them
}