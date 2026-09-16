rule TTP_XOR_WriteProcessMemory_c46b {
  strings:
    $key_c46b = { 93 19 [2] a1 3b [2] a7 0e [2] 89 0e [2] b6 12 }

  condition:
    any of them
}