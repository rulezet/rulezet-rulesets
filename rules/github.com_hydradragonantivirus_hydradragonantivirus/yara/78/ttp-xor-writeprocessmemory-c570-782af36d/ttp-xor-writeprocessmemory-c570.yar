rule TTP_XOR_WriteProcessMemory_c570 {
  strings:
    $key_c570 = { 92 02 [2] a0 20 [2] a6 15 [2] 88 15 [2] b7 09 }

  condition:
    any of them
}