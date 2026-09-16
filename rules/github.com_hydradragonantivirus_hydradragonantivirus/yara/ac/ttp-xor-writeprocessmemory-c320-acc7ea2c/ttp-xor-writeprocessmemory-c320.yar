rule TTP_XOR_WriteProcessMemory_c320 {
  strings:
    $key_c320 = { 94 52 [2] a6 70 [2] a0 45 [2] 8e 45 [2] b1 59 }

  condition:
    any of them
}