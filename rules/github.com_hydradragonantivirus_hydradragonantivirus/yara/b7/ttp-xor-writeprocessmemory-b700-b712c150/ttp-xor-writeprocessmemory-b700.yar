rule TTP_XOR_WriteProcessMemory_b700 {
  strings:
    $key_b700 = { e0 72 [2] d2 50 [2] d4 65 [2] fa 65 [2] c5 79 }

  condition:
    any of them
}