rule TTP_XOR_WriteProcessMemory_d20b {
  strings:
    $key_d20b = { 85 79 [2] b7 5b [2] b1 6e [2] 9f 6e [2] a0 72 }

  condition:
    any of them
}