rule TTP_XOR_WriteProcessMemory_b535 {
  strings:
    $key_b535 = { e2 47 [2] d0 65 [2] d6 50 [2] f8 50 [2] c7 4c }

  condition:
    any of them
}