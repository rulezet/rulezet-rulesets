rule TTP_XOR_WriteProcessMemory_c572 {
  strings:
    $key_c572 = { 92 00 [2] a0 22 [2] a6 17 [2] 88 17 [2] b7 0b }

  condition:
    any of them
}