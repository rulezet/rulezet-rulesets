rule TTP_XOR_WriteProcessMemory_c567 {
  strings:
    $key_c567 = { 92 15 [2] a0 37 [2] a6 02 [2] 88 02 [2] b7 1e }

  condition:
    any of them
}