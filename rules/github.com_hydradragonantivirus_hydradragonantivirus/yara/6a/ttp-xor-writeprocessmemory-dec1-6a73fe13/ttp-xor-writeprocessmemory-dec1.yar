rule TTP_XOR_WriteProcessMemory_dec1 {
  strings:
    $key_dec1 = { 89 b3 [2] bb 91 [2] bd a4 [2] 93 a4 [2] ac b8 }

  condition:
    any of them
}