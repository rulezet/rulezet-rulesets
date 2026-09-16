rule TTP_XOR_WriteProcessMemory_d310 {
  strings:
    $key_d310 = { 84 62 [2] b6 40 [2] b0 75 [2] 9e 75 [2] a1 69 }

  condition:
    any of them
}