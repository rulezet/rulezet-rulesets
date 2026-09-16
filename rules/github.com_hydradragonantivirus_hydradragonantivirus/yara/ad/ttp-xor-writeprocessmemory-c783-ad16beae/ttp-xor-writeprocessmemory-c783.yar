rule TTP_XOR_WriteProcessMemory_c783 {
  strings:
    $key_c783 = { 90 f1 [2] a2 d3 [2] a4 e6 [2] 8a e6 [2] b5 fa }

  condition:
    any of them
}