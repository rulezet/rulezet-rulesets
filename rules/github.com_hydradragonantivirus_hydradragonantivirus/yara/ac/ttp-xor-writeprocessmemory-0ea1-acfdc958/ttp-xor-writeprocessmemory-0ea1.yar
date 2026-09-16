rule TTP_XOR_WriteProcessMemory_0ea1 {
  strings:
    $key_0ea1 = { 59 d3 [2] 6b f1 [2] 6d c4 [2] 43 c4 [2] 7c d8 }

  condition:
    any of them
}