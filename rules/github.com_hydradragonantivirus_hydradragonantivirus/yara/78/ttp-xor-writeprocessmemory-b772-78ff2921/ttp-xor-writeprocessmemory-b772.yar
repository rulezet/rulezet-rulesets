rule TTP_XOR_WriteProcessMemory_b772 {
  strings:
    $key_b772 = { e0 00 [2] d2 22 [2] d4 17 [2] fa 17 [2] c5 0b }

  condition:
    any of them
}