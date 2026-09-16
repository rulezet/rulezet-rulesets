rule TTP_XOR_WriteProcessMemory_c392 {
  strings:
    $key_c392 = { 94 e0 [2] a6 c2 [2] a0 f7 [2] 8e f7 [2] b1 eb }

  condition:
    any of them
}