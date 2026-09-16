rule TTP_XOR_WriteProcessMemory_d097 {
  strings:
    $key_d097 = { 87 e5 [2] b5 c7 [2] b3 f2 [2] 9d f2 [2] a2 ee }

  condition:
    any of them
}