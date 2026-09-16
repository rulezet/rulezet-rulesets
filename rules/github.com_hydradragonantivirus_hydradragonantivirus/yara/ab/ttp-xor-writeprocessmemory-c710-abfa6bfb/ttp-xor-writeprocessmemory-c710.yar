rule TTP_XOR_WriteProcessMemory_c710 {
  strings:
    $key_c710 = { 90 62 [2] a2 40 [2] a4 75 [2] 8a 75 [2] b5 69 }

  condition:
    any of them
}