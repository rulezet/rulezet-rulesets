rule TTP_XOR_WriteProcessMemory_cc97 {
  strings:
    $key_cc97 = { 9b e5 [2] a9 c7 [2] af f2 [2] 81 f2 [2] be ee }

  condition:
    any of them
}