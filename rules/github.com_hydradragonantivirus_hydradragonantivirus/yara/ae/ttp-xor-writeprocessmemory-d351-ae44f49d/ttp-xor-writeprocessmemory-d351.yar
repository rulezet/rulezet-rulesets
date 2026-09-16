rule TTP_XOR_WriteProcessMemory_d351 {
  strings:
    $key_d351 = { 84 23 [2] b6 01 [2] b0 34 [2] 9e 34 [2] a1 28 }

  condition:
    any of them
}