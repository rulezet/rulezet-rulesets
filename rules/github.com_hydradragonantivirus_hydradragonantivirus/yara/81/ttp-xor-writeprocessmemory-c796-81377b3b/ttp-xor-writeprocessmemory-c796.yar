rule TTP_XOR_WriteProcessMemory_c796 {
  strings:
    $key_c796 = { 90 e4 [2] a2 c6 [2] a4 f3 [2] 8a f3 [2] b5 ef }

  condition:
    any of them
}