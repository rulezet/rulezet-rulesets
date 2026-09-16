rule TTP_XOR_WriteProcessMemory_b5a3 {
  strings:
    $key_b5a3 = { e2 d1 [2] d0 f3 [2] d6 c6 [2] f8 c6 [2] c7 da }

  condition:
    any of them
}