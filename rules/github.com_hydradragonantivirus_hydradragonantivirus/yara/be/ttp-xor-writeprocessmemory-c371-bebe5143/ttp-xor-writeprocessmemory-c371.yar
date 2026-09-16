rule TTP_XOR_WriteProcessMemory_c371 {
  strings:
    $key_c371 = { 94 03 [2] a6 21 [2] a0 14 [2] 8e 14 [2] b1 08 }

  condition:
    any of them
}