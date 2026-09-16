rule TTP_XOR_WriteProcessMemory_d622 {
  strings:
    $key_d622 = { 81 50 [2] b3 72 [2] b5 47 [2] 9b 47 [2] a4 5b }

  condition:
    any of them
}