rule TTP_XOR_WriteProcessMemory_d46b {
  strings:
    $key_d46b = { 83 19 [2] b1 3b [2] b7 0e [2] 99 0e [2] a6 12 }

  condition:
    any of them
}