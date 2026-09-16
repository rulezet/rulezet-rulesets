rule TTP_XOR_WriteProcessMemory_d285 {
  strings:
    $key_d285 = { 85 f7 [2] b7 d5 [2] b1 e0 [2] 9f e0 [2] a0 fc }

  condition:
    any of them
}