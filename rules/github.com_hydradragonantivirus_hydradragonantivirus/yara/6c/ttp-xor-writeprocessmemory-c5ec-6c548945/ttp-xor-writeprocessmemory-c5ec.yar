rule TTP_XOR_WriteProcessMemory_c5ec {
  strings:
    $key_c5ec = { 92 9e [2] a0 bc [2] a6 89 [2] 88 89 [2] b7 95 }

  condition:
    any of them
}