rule TTP_XOR_WriteProcessMemory_b5b2 {
  strings:
    $key_b5b2 = { e2 c0 [2] d0 e2 [2] d6 d7 [2] f8 d7 [2] c7 cb }

  condition:
    any of them
}