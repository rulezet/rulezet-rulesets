rule TTP_XOR_WriteProcessMemory_b1c5 {
  strings:
    $key_b1c5 = { e6 b7 [2] d4 95 [2] d2 a0 [2] fc a0 [2] c3 bc }

  condition:
    any of them
}