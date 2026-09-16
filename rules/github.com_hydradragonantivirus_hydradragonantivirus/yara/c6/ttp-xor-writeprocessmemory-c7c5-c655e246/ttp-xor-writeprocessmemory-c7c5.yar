rule TTP_XOR_WriteProcessMemory_c7c5 {
  strings:
    $key_c7c5 = { 90 b7 [2] a2 95 [2] a4 a0 [2] 8a a0 [2] b5 bc }

  condition:
    any of them
}