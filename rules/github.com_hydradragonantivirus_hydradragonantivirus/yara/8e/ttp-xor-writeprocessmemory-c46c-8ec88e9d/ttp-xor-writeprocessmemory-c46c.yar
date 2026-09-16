rule TTP_XOR_WriteProcessMemory_c46c {
  strings:
    $key_c46c = { 93 1e [2] a1 3c [2] a7 09 [2] 89 09 [2] b6 15 }

  condition:
    any of them
}