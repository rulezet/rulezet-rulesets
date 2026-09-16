rule TTP_XOR_WriteProcessMemory_d760 {
  strings:
    $key_d760 = { 80 12 [2] b2 30 [2] b4 05 [2] 9a 05 [2] a5 19 }

  condition:
    any of them
}