rule TTP_XOR_WriteProcessMemory_d4a4 {
  strings:
    $key_d4a4 = { 83 d6 [2] b1 f4 [2] b7 c1 [2] 99 c1 [2] a6 dd }

  condition:
    any of them
}