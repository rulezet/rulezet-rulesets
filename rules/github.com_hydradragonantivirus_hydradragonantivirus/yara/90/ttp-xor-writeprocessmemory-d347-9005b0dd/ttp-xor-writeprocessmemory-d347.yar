rule TTP_XOR_WriteProcessMemory_d347 {
  strings:
    $key_d347 = { 84 35 [2] b6 17 [2] b0 22 [2] 9e 22 [2] a1 3e }

  condition:
    any of them
}