rule TTP_XOR_WriteProcessMemory_c532 {
  strings:
    $key_c532 = { 92 40 [2] a0 62 [2] a6 57 [2] 88 57 [2] b7 4b }

  condition:
    any of them
}