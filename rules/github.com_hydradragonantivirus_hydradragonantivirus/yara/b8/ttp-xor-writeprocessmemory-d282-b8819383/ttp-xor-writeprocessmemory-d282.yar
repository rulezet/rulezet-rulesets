rule TTP_XOR_WriteProcessMemory_d282 {
  strings:
    $key_d282 = { 85 f0 [2] b7 d2 [2] b1 e7 [2] 9f e7 [2] a0 fb }

  condition:
    any of them
}