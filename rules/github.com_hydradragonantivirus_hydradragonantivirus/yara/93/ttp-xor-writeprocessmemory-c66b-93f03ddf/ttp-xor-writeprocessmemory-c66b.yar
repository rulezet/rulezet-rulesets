rule TTP_XOR_WriteProcessMemory_c66b {
  strings:
    $key_c66b = { 91 19 [2] a3 3b [2] a5 0e [2] 8b 0e [2] b4 12 }

  condition:
    any of them
}