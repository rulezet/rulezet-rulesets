rule TTP_XOR_WriteProcessMemory_c190 {
  strings:
    $key_c190 = { 96 e2 [2] a4 c0 [2] a2 f5 [2] 8c f5 [2] b3 e9 }

  condition:
    any of them
}