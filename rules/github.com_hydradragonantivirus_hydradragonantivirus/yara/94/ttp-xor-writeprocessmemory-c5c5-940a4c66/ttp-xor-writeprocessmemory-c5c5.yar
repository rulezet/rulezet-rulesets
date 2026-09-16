rule TTP_XOR_WriteProcessMemory_c5c5 {
  strings:
    $key_c5c5 = { 92 b7 [2] a0 95 [2] a6 a0 [2] 88 a0 [2] b7 bc }

  condition:
    any of them
}