rule TTP_XOR_WriteProcessMemory_d440 {
  strings:
    $key_d440 = { 83 32 [2] b1 10 [2] b7 25 [2] 99 25 [2] a6 39 }

  condition:
    any of them
}