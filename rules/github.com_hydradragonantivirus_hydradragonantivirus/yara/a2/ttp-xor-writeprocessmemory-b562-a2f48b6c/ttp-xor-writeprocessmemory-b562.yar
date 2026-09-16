rule TTP_XOR_WriteProcessMemory_b562 {
  strings:
    $key_b562 = { e2 10 [2] d0 32 [2] d6 07 [2] f8 07 [2] c7 1b }

  condition:
    any of them
}