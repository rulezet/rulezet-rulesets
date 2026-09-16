rule TTP_XOR_WriteProcessMemory_d151 {
  strings:
    $key_d151 = { 86 23 [2] b4 01 [2] b2 34 [2] 9c 34 [2] a3 28 }

  condition:
    any of them
}