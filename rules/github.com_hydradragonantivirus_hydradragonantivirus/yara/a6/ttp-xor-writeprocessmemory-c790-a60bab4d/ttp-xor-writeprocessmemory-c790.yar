rule TTP_XOR_WriteProcessMemory_c790 {
  strings:
    $key_c790 = { 90 e2 [2] a2 c0 [2] a4 f5 [2] 8a f5 [2] b5 e9 }

  condition:
    any of them
}