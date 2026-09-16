rule TTP_XOR_WriteProcessMemory_b421 {
  strings:
    $key_b421 = { e3 53 [2] d1 71 [2] d7 44 [2] f9 44 [2] c6 58 }

  condition:
    any of them
}