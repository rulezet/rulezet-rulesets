rule TTP_XOR_WriteProcessMemory_c183 {
  strings:
    $key_c183 = { 96 f1 [2] a4 d3 [2] a2 e6 [2] 8c e6 [2] b3 fa }

  condition:
    any of them
}