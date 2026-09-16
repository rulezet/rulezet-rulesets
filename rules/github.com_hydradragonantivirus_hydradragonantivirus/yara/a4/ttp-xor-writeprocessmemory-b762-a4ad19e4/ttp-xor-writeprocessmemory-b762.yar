rule TTP_XOR_WriteProcessMemory_b762 {
  strings:
    $key_b762 = { e0 10 [2] d2 32 [2] d4 07 [2] fa 07 [2] c5 1b }

  condition:
    any of them
}