rule TTP_XOR_WriteProcessMemory_c221 {
  strings:
    $key_c221 = { 95 53 [2] a7 71 [2] a1 44 [2] 8f 44 [2] b0 58 }

  condition:
    any of them
}