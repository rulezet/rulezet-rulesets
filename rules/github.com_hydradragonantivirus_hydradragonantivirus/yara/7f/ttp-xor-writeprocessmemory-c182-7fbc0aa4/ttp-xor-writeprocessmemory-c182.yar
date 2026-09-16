rule TTP_XOR_WriteProcessMemory_c182 {
  strings:
    $key_c182 = { 96 f0 [2] a4 d2 [2] a2 e7 [2] 8c e7 [2] b3 fb }

  condition:
    any of them
}