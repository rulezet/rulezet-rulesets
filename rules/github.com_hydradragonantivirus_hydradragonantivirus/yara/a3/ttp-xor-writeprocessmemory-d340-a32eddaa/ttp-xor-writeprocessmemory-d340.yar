rule TTP_XOR_WriteProcessMemory_d340 {
  strings:
    $key_d340 = { 84 32 [2] b6 10 [2] b0 25 [2] 9e 25 [2] a1 39 }

  condition:
    any of them
}