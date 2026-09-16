rule TTP_XOR_WriteProcessMemory_b764 {
  strings:
    $key_b764 = { e0 16 [2] d2 34 [2] d4 01 [2] fa 01 [2] c5 1d }

  condition:
    any of them
}