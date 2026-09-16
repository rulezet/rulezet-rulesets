rule TTP_XOR_WriteProcessMemory_c31c {
  strings:
    $key_c31c = { 94 6e [2] a6 4c [2] a0 79 [2] 8e 79 [2] b1 65 }

  condition:
    any of them
}