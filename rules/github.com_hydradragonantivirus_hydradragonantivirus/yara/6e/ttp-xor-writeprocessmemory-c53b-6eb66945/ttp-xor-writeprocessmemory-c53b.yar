rule TTP_XOR_WriteProcessMemory_c53b {
  strings:
    $key_c53b = { 92 49 [2] a0 6b [2] a6 5e [2] 88 5e [2] b7 42 }

  condition:
    any of them
}