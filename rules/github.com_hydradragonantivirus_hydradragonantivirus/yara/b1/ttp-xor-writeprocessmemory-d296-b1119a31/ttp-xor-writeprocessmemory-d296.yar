rule TTP_XOR_WriteProcessMemory_d296 {
  strings:
    $key_d296 = { 85 e4 [2] b7 c6 [2] b1 f3 [2] 9f f3 [2] a0 ef }

  condition:
    any of them
}