rule TTP_XOR_WriteProcessMemory_b557 {
  strings:
    $key_b557 = { e2 25 [2] d0 07 [2] d6 32 [2] f8 32 [2] c7 2e }

  condition:
    any of them
}