rule TTP_XOR_WriteProcessMemory_d402 {
  strings:
    $key_d402 = { 83 70 [2] b1 52 [2] b7 67 [2] 99 67 [2] a6 7b }

  condition:
    any of them
}