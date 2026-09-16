rule TTP_XOR_WriteProcessMemory_d243 {
  strings:
    $key_d243 = { 85 31 [2] b7 13 [2] b1 26 [2] 9f 26 [2] a0 3a }

  condition:
    any of them
}