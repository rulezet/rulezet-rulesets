rule TTP_XOR_WriteProcessMemory_c577 {
  strings:
    $key_c577 = { 92 05 [2] a0 27 [2] a6 12 [2] 88 12 [2] b7 0e }

  condition:
    any of them
}