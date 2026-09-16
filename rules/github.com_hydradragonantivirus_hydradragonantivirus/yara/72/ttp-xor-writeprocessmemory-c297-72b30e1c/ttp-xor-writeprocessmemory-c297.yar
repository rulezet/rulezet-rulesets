rule TTP_XOR_WriteProcessMemory_c297 {
  strings:
    $key_c297 = { 95 e5 [2] a7 c7 [2] a1 f2 [2] 8f f2 [2] b0 ee }

  condition:
    any of them
}