rule TTP_XOR_WriteProcessMemory_c1c4 {
  strings:
    $key_c1c4 = { 96 b6 [2] a4 94 [2] a2 a1 [2] 8c a1 [2] b3 bd }

  condition:
    any of them
}