rule TTP_XOR_WriteProcessMemory_b771 {
  strings:
    $key_b771 = { e0 03 [2] d2 21 [2] d4 14 [2] fa 14 [2] c5 08 }

  condition:
    any of them
}