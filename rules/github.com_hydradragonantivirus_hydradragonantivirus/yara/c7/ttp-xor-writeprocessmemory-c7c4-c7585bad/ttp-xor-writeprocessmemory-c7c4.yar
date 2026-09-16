rule TTP_XOR_WriteProcessMemory_c7c4 {
  strings:
    $key_c7c4 = { 90 b6 [2] a2 94 [2] a4 a1 [2] 8a a1 [2] b5 bd }

  condition:
    any of them
}