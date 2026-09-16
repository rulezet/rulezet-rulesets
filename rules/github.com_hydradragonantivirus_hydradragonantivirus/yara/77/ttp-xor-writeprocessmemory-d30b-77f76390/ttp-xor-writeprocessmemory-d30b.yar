rule TTP_XOR_WriteProcessMemory_d30b {
  strings:
    $key_d30b = { 84 79 [2] b6 5b [2] b0 6e [2] 9e 6e [2] a1 72 }

  condition:
    any of them
}