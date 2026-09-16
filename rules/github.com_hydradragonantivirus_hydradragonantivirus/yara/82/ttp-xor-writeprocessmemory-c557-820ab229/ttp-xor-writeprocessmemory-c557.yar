rule TTP_XOR_WriteProcessMemory_c557 {
  strings:
    $key_c557 = { 92 25 [2] a0 07 [2] a6 32 [2] 88 32 [2] b7 2e }

  condition:
    any of them
}