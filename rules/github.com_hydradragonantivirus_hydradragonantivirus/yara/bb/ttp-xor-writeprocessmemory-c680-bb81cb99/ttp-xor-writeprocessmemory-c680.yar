rule TTP_XOR_WriteProcessMemory_c680 {
  strings:
    $key_c680 = { 91 f2 [2] a3 d0 [2] a5 e5 [2] 8b e5 [2] b4 f9 }

  condition:
    any of them
}