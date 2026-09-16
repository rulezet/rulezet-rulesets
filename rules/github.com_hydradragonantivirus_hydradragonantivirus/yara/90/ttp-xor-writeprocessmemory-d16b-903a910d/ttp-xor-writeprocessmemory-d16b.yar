rule TTP_XOR_WriteProcessMemory_d16b {
  strings:
    $key_d16b = { 86 19 [2] b4 3b [2] b2 0e [2] 9c 0e [2] a3 12 }

  condition:
    any of them
}