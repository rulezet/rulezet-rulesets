rule TTP_XOR_WriteProcessMemory_b517 {
  strings:
    $key_b517 = { e2 65 [2] d0 47 [2] d6 72 [2] f8 72 [2] c7 6e }

  condition:
    any of them
}