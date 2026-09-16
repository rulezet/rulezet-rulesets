rule TTP_XOR_WriteProcessMemory_c097 {
  strings:
    $key_c097 = { 97 e5 [2] a5 c7 [2] a3 f2 [2] 8d f2 [2] b2 ee }

  condition:
    any of them
}