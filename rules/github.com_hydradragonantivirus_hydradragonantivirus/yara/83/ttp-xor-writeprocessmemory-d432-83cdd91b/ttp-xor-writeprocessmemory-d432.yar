rule TTP_XOR_WriteProcessMemory_d432 {
  strings:
    $key_d432 = { 83 40 [2] b1 62 [2] b7 57 [2] 99 57 [2] a6 4b }

  condition:
    any of them
}