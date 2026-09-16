rule TTP_XOR_WriteProcessMemory_c197 {
  strings:
    $key_c197 = { 96 e5 [2] a4 c7 [2] a2 f2 [2] 8c f2 [2] b3 ee }

  condition:
    any of them
}