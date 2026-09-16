rule TTP_XOR_WriteProcessMemory_c75b {
  strings:
    $key_c75b = { 90 29 [2] a2 0b [2] a4 3e [2] 8a 3e [2] b5 22 }

  condition:
    any of them
}