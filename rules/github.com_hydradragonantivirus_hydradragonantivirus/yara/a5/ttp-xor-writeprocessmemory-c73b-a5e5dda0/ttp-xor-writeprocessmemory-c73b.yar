rule TTP_XOR_WriteProcessMemory_c73b {
  strings:
    $key_c73b = { 90 49 [2] a2 6b [2] a4 5e [2] 8a 5e [2] b5 42 }

  condition:
    any of them
}