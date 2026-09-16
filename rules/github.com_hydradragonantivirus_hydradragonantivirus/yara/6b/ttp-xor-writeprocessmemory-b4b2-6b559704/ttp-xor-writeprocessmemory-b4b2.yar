rule TTP_XOR_WriteProcessMemory_b4b2 {
  strings:
    $key_b4b2 = { e3 c0 [2] d1 e2 [2] d7 d7 [2] f9 d7 [2] c6 cb }

  condition:
    any of them
}