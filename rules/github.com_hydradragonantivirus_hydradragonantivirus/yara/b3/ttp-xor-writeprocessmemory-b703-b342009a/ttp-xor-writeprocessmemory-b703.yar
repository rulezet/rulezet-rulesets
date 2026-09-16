rule TTP_XOR_WriteProcessMemory_b703 {
  strings:
    $key_b703 = { e0 71 [2] d2 53 [2] d4 66 [2] fa 66 [2] c5 7a }

  condition:
    any of them
}