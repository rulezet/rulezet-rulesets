rule TTP_XOR_WriteProcessMemory_c26b {
  strings:
    $key_c26b = { 95 19 [2] a7 3b [2] a1 0e [2] 8f 0e [2] b0 12 }

  condition:
    any of them
}