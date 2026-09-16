rule TTP_XOR_WriteProcessMemory_c5c4 {
  strings:
    $key_c5c4 = { 92 b6 [2] a0 94 [2] a6 a1 [2] 88 a1 [2] b7 bd }

  condition:
    any of them
}