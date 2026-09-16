rule TTP_XOR_WriteProcessMemory_d27b {
  strings:
    $key_d27b = { 85 09 [2] b7 2b [2] b1 1e [2] 9f 1e [2] a0 02 }

  condition:
    any of them
}