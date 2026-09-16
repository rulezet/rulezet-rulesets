rule TTP_XOR_WriteProcessMemory_d260 {
  strings:
    $key_d260 = { 85 12 [2] b7 30 [2] b1 05 [2] 9f 05 [2] a0 19 }

  condition:
    any of them
}