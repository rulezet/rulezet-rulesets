rule TTP_XOR_WriteProcessMemory_36a1 {
  strings:
    $key_36a1 = { 61 d3 [2] 53 f1 [2] 55 c4 [2] 7b c4 [2] 44 d8 }

  condition:
    any of them
}