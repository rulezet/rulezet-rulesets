rule TTP_XOR_WriteProcessMemory_d096 {
  strings:
    $key_d096 = { 87 e4 [2] b5 c6 [2] b3 f3 [2] 9d f3 [2] a2 ef }

  condition:
    any of them
}