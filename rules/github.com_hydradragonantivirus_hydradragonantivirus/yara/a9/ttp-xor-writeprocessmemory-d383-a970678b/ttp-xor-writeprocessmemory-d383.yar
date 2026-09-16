rule TTP_XOR_WriteProcessMemory_d383 {
  strings:
    $key_d383 = { 84 f1 [2] b6 d3 [2] b0 e6 [2] 9e e6 [2] a1 fa }

  condition:
    any of them
}