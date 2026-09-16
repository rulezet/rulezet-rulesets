rule TTP_XOR_WriteProcessMemory_b776 {
  strings:
    $key_b776 = { e0 04 [2] d2 26 [2] d4 13 [2] fa 13 [2] c5 0f }

  condition:
    any of them
}