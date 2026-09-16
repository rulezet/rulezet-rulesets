rule TTP_XOR_WriteProcessMemory_0681 {
  strings:
    $key_0681 = { 51 f3 [2] 63 d1 [2] 65 e4 [2] 4b e4 [2] 74 f8 }

  condition:
    any of them
}