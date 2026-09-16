rule TTP_XOR_WriteProcessMemory_d790 {
  strings:
    $key_d790 = { 80 e2 [2] b2 c0 [2] b4 f5 [2] 9a f5 [2] a5 e9 }

  condition:
    any of them
}