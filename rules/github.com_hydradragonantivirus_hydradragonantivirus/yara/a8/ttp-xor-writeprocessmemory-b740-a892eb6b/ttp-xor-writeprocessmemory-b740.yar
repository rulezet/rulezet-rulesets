rule TTP_XOR_WriteProcessMemory_b740 {
  strings:
    $key_b740 = { e0 32 [2] d2 10 [2] d4 25 [2] fa 25 [2] c5 39 }

  condition:
    any of them
}