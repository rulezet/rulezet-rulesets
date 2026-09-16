rule TTP_XOR_WriteProcessMemory_14a1 {
  strings:
    $key_14a1 = { 43 d3 [2] 71 f1 [2] 77 c4 [2] 59 c4 [2] 66 d8 }

  condition:
    any of them
}