rule TTP_XOR_WriteProcessMemory_a557 {
  strings:
    $key_a557 = { f2 25 [2] c0 07 [2] c6 32 [2] e8 32 [2] d7 2e }

  condition:
    any of them
}