rule TTP_XOR_WriteProcessMemory_2776 {
  strings:
    $key_2776 = { 70 04 [2] 42 26 [2] 44 13 [2] 6a 13 [2] 55 0f }

  condition:
    any of them
}