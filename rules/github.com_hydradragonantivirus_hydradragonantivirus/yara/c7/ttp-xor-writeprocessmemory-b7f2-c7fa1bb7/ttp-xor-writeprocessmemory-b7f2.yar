rule TTP_XOR_WriteProcessMemory_b7f2 {
  strings:
    $key_b7f2 = { e0 80 [2] d2 a2 [2] d4 97 [2] fa 97 [2] c5 8b }

  condition:
    any of them
}