rule TTP_XOR_WriteProcessMemory_d182 {
  strings:
    $key_d182 = { 86 f0 [2] b4 d2 [2] b2 e7 [2] 9c e7 [2] a3 fb }

  condition:
    any of them
}