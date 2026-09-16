rule TTP_XOR_WriteProcessMemory_c681 {
  strings:
    $key_c681 = { 91 f3 [2] a3 d1 [2] a5 e4 [2] 8b e4 [2] b4 f8 }

  condition:
    any of them
}