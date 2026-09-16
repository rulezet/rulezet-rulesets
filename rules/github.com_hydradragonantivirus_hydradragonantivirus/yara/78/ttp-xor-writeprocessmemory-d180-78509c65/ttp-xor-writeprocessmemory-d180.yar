rule TTP_XOR_WriteProcessMemory_d180 {
  strings:
    $key_d180 = { 86 f2 [2] b4 d0 [2] b2 e5 [2] 9c e5 [2] a3 f9 }

  condition:
    any of them
}