rule TTP_XOR_WriteProcessMemory_d583 {
  strings:
    $key_d583 = { 82 f1 [2] b0 d3 [2] b6 e6 [2] 98 e6 [2] a7 fa }

  condition:
    any of them
}