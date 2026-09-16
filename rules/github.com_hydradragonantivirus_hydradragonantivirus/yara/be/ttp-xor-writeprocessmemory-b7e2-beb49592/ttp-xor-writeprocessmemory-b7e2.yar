rule TTP_XOR_WriteProcessMemory_b7e2 {
  strings:
    $key_b7e2 = { e0 90 [2] d2 b2 [2] d4 87 [2] fa 87 [2] c5 9b }

  condition:
    any of them
}