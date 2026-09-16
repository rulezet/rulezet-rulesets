rule TTP_XOR_WriteProcessMemory_cc91 {
  strings:
    $key_cc91 = { 9b e3 [2] a9 c1 [2] af f4 [2] 81 f4 [2] be e8 }

  condition:
    any of them
}