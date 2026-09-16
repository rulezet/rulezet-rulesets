rule TTP_XOR_WriteProcessMemory_02a1 {
  strings:
    $key_02a1 = { 55 d3 [2] 67 f1 [2] 61 c4 [2] 4f c4 [2] 70 d8 }

  condition:
    any of them
}