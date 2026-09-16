rule TTP_XOR_WriteProcessMemory_b766 {
  strings:
    $key_b766 = { e0 14 [2] d2 36 [2] d4 03 [2] fa 03 [2] c5 1f }

  condition:
    any of them
}