rule TTP_XOR_WriteProcessMemory_44a1 {
  strings:
    $key_44a1 = { 13 d3 [2] 21 f1 [2] 27 c4 [2] 09 c4 [2] 36 d8 }

  condition:
    any of them
}