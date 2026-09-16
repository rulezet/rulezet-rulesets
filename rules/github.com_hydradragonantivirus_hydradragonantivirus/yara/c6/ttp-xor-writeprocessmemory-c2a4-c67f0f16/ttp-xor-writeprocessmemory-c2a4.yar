rule TTP_XOR_WriteProcessMemory_c2a4 {
  strings:
    $key_c2a4 = { 95 d6 [2] a7 f4 [2] a1 c1 [2] 8f c1 [2] b0 dd }

  condition:
    any of them
}