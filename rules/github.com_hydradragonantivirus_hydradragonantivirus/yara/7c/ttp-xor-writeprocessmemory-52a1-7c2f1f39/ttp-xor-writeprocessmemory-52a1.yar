rule TTP_XOR_WriteProcessMemory_52a1 {
  strings:
    $key_52a1 = { 05 d3 [2] 37 f1 [2] 31 c4 [2] 1f c4 [2] 20 d8 }

  condition:
    any of them
}