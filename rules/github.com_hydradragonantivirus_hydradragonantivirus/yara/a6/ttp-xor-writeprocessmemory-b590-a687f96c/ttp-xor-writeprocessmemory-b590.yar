rule TTP_XOR_WriteProcessMemory_b590 {
  strings:
    $key_b590 = { e2 e2 [2] d0 c0 [2] d6 f5 [2] f8 f5 [2] c7 e9 }

  condition:
    any of them
}