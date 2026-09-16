rule TTP_XOR_WriteProcessMemory_c3ec {
  strings:
    $key_c3ec = { 94 9e [2] a6 bc [2] a0 89 [2] 8e 89 [2] b1 95 }

  condition:
    any of them
}