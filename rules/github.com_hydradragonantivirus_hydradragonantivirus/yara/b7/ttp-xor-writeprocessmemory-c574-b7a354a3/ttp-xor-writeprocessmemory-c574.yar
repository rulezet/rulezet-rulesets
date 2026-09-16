rule TTP_XOR_WriteProcessMemory_c574 {
  strings:
    $key_c574 = { 92 06 [2] a0 24 [2] a6 11 [2] 88 11 [2] b7 0d }

  condition:
    any of them
}