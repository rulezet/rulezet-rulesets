rule TTP_XOR_WriteProcessMemory_b7f7 {
  strings:
    $key_b7f7 = { e0 85 [2] d2 a7 [2] d4 92 [2] fa 92 [2] c5 8e }

  condition:
    any of them
}