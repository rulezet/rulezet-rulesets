rule TTP_XOR_WriteProcessMemory_cc92 {
  strings:
    $key_cc92 = { 9b e0 [2] a9 c2 [2] af f7 [2] 81 f7 [2] be eb }

  condition:
    any of them
}