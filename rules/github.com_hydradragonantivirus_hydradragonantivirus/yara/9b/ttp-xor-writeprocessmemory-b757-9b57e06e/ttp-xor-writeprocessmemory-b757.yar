rule TTP_XOR_WriteProcessMemory_b757 {
  strings:
    $key_b757 = { e0 25 [2] d2 07 [2] d4 32 [2] fa 32 [2] c5 2e }

  condition:
    any of them
}