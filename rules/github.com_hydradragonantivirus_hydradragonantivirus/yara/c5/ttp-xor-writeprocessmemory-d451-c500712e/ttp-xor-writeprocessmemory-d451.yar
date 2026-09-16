rule TTP_XOR_WriteProcessMemory_d451 {
  strings:
    $key_d451 = { 83 23 [2] b1 01 [2] b7 34 [2] 99 34 [2] a6 28 }

  condition:
    any of them
}