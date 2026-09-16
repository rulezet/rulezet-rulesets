rule TTP_XOR_WriteProcessMemory_b573 {
  strings:
    $key_b573 = { e2 01 [2] d0 23 [2] d6 16 [2] f8 16 [2] c7 0a }

  condition:
    any of them
}