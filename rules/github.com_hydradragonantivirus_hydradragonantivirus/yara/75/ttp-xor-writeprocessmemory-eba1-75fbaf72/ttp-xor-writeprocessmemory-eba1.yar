rule TTP_XOR_WriteProcessMemory_eba1 {
  strings:
    $key_eba1 = { bc d3 [2] 8e f1 [2] 88 c4 [2] a6 c4 [2] 99 d8 }

  condition:
    any of them
}