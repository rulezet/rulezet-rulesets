rule TTP_XOR_WriteProcessMemory_c383 {
  strings:
    $key_c383 = { 94 f1 [2] a6 d3 [2] a0 e6 [2] 8e e6 [2] b1 fa }

  condition:
    any of them
}