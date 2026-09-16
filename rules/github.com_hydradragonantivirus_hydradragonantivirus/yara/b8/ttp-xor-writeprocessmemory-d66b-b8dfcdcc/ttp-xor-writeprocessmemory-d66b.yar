rule TTP_XOR_WriteProcessMemory_d66b {
  strings:
    $key_d66b = { 81 19 [2] b3 3b [2] b5 0e [2] 9b 0e [2] a4 12 }

  condition:
    any of them
}