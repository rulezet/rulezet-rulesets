rule TTP_XOR_WriteProcessMemory_c500 {
  strings:
    $key_c500 = { 92 72 [2] a0 50 [2] a6 65 [2] 88 65 [2] b7 79 }

  condition:
    any of them
}