rule TTP_XOR_WriteProcessMemory_c15b {
  strings:
    $key_c15b = { 96 29 [2] a4 0b [2] a2 3e [2] 8c 3e [2] b3 22 }

  condition:
    any of them
}