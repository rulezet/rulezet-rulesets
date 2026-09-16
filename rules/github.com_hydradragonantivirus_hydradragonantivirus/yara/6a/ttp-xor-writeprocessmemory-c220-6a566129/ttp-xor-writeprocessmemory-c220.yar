rule TTP_XOR_WriteProcessMemory_c220 {
  strings:
    $key_c220 = { 95 52 [2] a7 70 [2] a1 45 [2] 8f 45 [2] b0 59 }

  condition:
    any of them
}