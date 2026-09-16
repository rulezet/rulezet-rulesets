rule TTP_XOR_WriteProcessMemory_d247 {
  strings:
    $key_d247 = { 85 35 [2] b7 17 [2] b1 22 [2] 9f 22 [2] a0 3e }

  condition:
    any of them
}