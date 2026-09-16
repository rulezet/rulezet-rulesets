rule TTP_XOR_WriteProcessMemory_d630 {
  strings:
    $key_d630 = { 81 42 [2] b3 60 [2] b5 55 [2] 9b 55 [2] a4 49 }

  condition:
    any of them
}