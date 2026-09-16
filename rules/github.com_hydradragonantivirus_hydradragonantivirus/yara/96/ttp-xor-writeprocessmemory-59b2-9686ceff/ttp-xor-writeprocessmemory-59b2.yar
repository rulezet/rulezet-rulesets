rule TTP_XOR_WriteProcessMemory_59b2 {
  strings:
    $key_59b2 = { 0e c0 [2] 3c e2 [2] 3a d7 [2] 14 d7 [2] 2b cb }

  condition:
    any of them
}