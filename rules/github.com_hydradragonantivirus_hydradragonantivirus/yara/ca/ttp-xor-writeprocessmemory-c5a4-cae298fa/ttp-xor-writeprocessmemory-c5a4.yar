rule TTP_XOR_WriteProcessMemory_c5a4 {
  strings:
    $key_c5a4 = { 92 d6 [2] a0 f4 [2] a6 c1 [2] 88 c1 [2] b7 dd }

  condition:
    any of them
}