rule TTP_XOR_WriteProcessMemory_b1a6 {
  strings:
    $key_b1a6 = { e6 d4 [2] d4 f6 [2] d2 c3 [2] fc c3 [2] c3 df }

  condition:
    any of them
}