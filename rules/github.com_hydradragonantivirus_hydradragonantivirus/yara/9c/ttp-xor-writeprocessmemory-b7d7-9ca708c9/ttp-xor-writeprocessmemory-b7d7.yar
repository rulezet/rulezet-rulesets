rule TTP_XOR_WriteProcessMemory_b7d7 {
  strings:
    $key_b7d7 = { e0 a5 [2] d2 87 [2] d4 b2 [2] fa b2 [2] c5 ae }

  condition:
    any of them
}