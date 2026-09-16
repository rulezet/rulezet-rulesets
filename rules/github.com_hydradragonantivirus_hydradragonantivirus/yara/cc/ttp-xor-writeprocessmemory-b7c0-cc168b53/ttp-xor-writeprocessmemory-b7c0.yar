rule TTP_XOR_WriteProcessMemory_b7c0 {
  strings:
    $key_b7c0 = { e0 b2 [2] d2 90 [2] d4 a5 [2] fa a5 [2] c5 b9 }

  condition:
    any of them
}