rule TTP_XOR_WriteProcessMemory_c1b5 {
  strings:
    $key_c1b5 = { 96 c7 [2] a4 e5 [2] a2 d0 [2] 8c d0 [2] b3 cc }

  condition:
    any of them
}