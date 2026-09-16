rule TTP_XOR_WriteProcessMemory_c74b {
  strings:
    $key_c74b = { 90 39 [2] a2 1b [2] a4 2e [2] 8a 2e [2] b5 32 }

  condition:
    any of them
}