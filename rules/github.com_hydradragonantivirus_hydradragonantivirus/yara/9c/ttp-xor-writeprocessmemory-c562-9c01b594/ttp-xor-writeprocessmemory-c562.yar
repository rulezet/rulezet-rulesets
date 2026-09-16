rule TTP_XOR_WriteProcessMemory_c562 {
  strings:
    $key_c562 = { 92 10 [2] a0 32 [2] a6 07 [2] 88 07 [2] b7 1b }

  condition:
    any of them
}