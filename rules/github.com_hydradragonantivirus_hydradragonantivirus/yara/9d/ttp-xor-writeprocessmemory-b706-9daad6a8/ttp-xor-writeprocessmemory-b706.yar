rule TTP_XOR_WriteProcessMemory_b706 {
  strings:
    $key_b706 = { e0 74 [2] d2 56 [2] d4 63 [2] fa 63 [2] c5 7f }

  condition:
    any of them
}