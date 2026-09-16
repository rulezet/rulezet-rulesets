rule TTP_XOR_WriteProcessMemory_cc93 {
  strings:
    $key_cc93 = { 9b e1 [2] a9 c3 [2] af f6 [2] 81 f6 [2] be ea }

  condition:
    any of them
}