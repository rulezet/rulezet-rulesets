rule TTP_XOR_WriteProcessMemory_c322 {
  strings:
    $key_c322 = { 94 50 [2] a6 72 [2] a0 47 [2] 8e 47 [2] b1 5b }

  condition:
    any of them
}