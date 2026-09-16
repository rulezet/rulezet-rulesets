rule TTP_XOR_WriteProcessMemory_b491 {
  strings:
    $key_b491 = { e3 e3 [2] d1 c1 [2] d7 f4 [2] f9 f4 [2] c6 e8 }

  condition:
    any of them
}