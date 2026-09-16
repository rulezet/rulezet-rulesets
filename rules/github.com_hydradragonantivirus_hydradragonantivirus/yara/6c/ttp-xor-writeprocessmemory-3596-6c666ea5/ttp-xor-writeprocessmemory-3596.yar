rule TTP_XOR_WriteProcessMemory_3596 {
  strings:
    $key_3596 = { 62 e4 [2] 50 c6 [2] 56 f3 [2] 78 f3 [2] 47 ef }

  condition:
    any of them
}