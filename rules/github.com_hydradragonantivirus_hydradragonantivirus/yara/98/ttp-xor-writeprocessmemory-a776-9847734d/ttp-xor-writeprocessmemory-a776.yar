rule TTP_XOR_WriteProcessMemory_a776 {
  strings:
    $key_a776 = { f0 04 [2] c2 26 [2] c4 13 [2] ea 13 [2] d5 0f }

  condition:
    any of them
}