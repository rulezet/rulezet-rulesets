rule TTP_XOR_WriteProcessMemory_d25b {
  strings:
    $key_d25b = { 85 29 [2] b7 0b [2] b1 3e [2] 9f 3e [2] a0 22 }

  condition:
    any of them
}