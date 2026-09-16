rule TTP_XOR_WriteProcessMemory_cba0 {
  strings:
    $key_cba0 = { 9c d2 [2] ae f0 [2] a8 c5 [2] 86 c5 [2] b9 d9 }

  condition:
    any of them
}