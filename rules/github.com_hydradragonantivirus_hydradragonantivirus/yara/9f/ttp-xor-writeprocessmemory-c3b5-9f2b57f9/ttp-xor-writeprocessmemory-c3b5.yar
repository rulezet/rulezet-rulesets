rule TTP_XOR_WriteProcessMemory_c3b5 {
  strings:
    $key_c3b5 = { 94 c7 [2] a6 e5 [2] a0 d0 [2] 8e d0 [2] b1 cc }

  condition:
    any of them
}