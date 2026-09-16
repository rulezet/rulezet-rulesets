rule TTP_XOR_WriteProcessMemory_fb80 {
  strings:
    $key_fb80 = { ac f2 [2] 9e d0 [2] 98 e5 [2] b6 e5 [2] 89 f9 }

  condition:
    any of them
}