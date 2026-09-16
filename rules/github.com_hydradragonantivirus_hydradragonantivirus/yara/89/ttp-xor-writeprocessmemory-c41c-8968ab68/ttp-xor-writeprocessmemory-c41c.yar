rule TTP_XOR_WriteProcessMemory_c41c {
  strings:
    $key_c41c = { 93 6e [2] a1 4c [2] a7 79 [2] 89 79 [2] b6 65 }

  condition:
    any of them
}