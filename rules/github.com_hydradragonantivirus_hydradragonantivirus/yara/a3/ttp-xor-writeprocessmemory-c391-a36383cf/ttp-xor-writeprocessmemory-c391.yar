rule TTP_XOR_WriteProcessMemory_c391 {
  strings:
    $key_c391 = { 94 e3 [2] a6 c1 [2] a0 f4 [2] 8e f4 [2] b1 e8 }

  condition:
    any of them
}