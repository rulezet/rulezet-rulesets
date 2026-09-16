rule TTP_XOR_WriteProcessMemory_b170 {
  strings:
    $key_b170 = { e6 02 [2] d4 20 [2] d2 15 [2] fc 15 [2] c3 09 }

  condition:
    any of them
}