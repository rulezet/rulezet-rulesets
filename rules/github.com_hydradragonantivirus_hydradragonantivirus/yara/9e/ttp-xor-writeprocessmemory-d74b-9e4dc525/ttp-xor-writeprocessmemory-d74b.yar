rule TTP_XOR_WriteProcessMemory_d74b {
  strings:
    $key_d74b = { 80 39 [2] b2 1b [2] b4 2e [2] 9a 2e [2] a5 32 }

  condition:
    any of them
}