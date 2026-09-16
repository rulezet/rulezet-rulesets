rule TTP_XOR_WriteProcessMemory_d7a4 {
  strings:
    $key_d7a4 = { 80 d6 [2] b2 f4 [2] b4 c1 [2] 9a c1 [2] a5 dd }

  condition:
    any of them
}