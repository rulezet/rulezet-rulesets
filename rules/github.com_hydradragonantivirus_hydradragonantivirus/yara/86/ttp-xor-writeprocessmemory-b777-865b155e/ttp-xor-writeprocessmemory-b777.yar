rule TTP_XOR_WriteProcessMemory_b777 {
  strings:
    $key_b777 = { e0 05 [2] d2 27 [2] d4 12 [2] fa 12 [2] c5 0e }

  condition:
    any of them
}