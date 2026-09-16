rule TTP_XOR_WriteProcessMemory_b743 {
  strings:
    $key_b743 = { e0 31 [2] d2 13 [2] d4 26 [2] fa 26 [2] c5 3a }

  condition:
    any of them
}