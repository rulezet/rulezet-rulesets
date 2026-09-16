rule TTP_XOR_WriteProcessMemory_d0a4 {
  strings:
    $key_d0a4 = { 87 d6 [2] b5 f4 [2] b3 c1 [2] 9d c1 [2] a2 dd }

  condition:
    any of them
}