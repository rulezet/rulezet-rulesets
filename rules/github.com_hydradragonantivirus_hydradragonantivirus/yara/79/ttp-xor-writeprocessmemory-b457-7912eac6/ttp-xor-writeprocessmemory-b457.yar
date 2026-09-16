rule TTP_XOR_WriteProcessMemory_b457 {
  strings:
    $key_b457 = { e3 25 [2] d1 07 [2] d7 32 [2] f9 32 [2] c6 2e }

  condition:
    any of them
}