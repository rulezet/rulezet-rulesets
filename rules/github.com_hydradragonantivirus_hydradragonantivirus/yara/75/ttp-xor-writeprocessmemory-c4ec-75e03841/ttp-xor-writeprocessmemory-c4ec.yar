rule TTP_XOR_WriteProcessMemory_c4ec {
  strings:
    $key_c4ec = { 93 9e [2] a1 bc [2] a7 89 [2] 89 89 [2] b6 95 }

  condition:
    any of them
}