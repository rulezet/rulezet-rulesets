rule TTP_XOR_WriteProcessMemory_d1a4 {
  strings:
    $key_d1a4 = { 86 d6 [2] b4 f4 [2] b2 c1 [2] 9c c1 [2] a3 dd }

  condition:
    any of them
}