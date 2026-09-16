rule TTP_XOR_WriteProcessMemory_c361 {
  strings:
    $key_c361 = { 94 13 [2] a6 31 [2] a0 04 [2] 8e 04 [2] b1 18 }

  condition:
    any of them
}