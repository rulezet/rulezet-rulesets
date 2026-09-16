rule TTP_XOR_WriteProcessMemory_c296 {
  strings:
    $key_c296 = { 95 e4 [2] a7 c6 [2] a1 f3 [2] 8f f3 [2] b0 ef }

  condition:
    any of them
}