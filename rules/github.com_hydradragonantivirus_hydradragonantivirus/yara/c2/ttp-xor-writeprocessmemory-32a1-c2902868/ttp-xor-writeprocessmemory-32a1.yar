rule TTP_XOR_WriteProcessMemory_32a1 {
  strings:
    $key_32a1 = { 65 d3 [2] 57 f1 [2] 51 c4 [2] 7f c4 [2] 40 d8 }

  condition:
    any of them
}