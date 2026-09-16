rule TTP_XOR_WriteProcessMemory_c196 {
  strings:
    $key_c196 = { 96 e4 [2] a4 c6 [2] a2 f3 [2] 8c f3 [2] b3 ef }

  condition:
    any of them
}