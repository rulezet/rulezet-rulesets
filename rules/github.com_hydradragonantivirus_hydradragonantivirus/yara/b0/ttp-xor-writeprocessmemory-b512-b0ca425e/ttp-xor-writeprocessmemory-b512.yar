rule TTP_XOR_WriteProcessMemory_b512 {
  strings:
    $key_b512 = { e2 60 [2] d0 42 [2] d6 77 [2] f8 77 [2] c7 6b }

  condition:
    any of them
}