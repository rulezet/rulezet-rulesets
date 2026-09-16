rule TTP_XOR_WriteProcessMemory_d70b {
  strings:
    $key_d70b = { 80 79 [2] b2 5b [2] b4 6e [2] 9a 6e [2] a5 72 }

  condition:
    any of them
}