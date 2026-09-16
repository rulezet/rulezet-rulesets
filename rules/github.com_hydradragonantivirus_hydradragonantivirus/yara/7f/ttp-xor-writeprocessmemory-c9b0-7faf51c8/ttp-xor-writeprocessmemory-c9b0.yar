rule TTP_XOR_WriteProcessMemory_c9b0 {
  strings:
    $key_c9b0 = { 9e c2 [2] ac e0 [2] aa d5 [2] 84 d5 [2] bb c9 }

  condition:
    any of them
}