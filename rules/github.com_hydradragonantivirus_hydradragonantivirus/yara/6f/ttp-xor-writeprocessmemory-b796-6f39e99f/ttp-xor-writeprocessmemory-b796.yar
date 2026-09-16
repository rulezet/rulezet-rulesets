rule TTP_XOR_WriteProcessMemory_b796 {
  strings:
    $key_b796 = { e0 e4 [2] d2 c6 [2] d4 f3 [2] fa f3 [2] c5 ef }

  condition:
    any of them
}