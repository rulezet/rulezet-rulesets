rule TTP_XOR_WriteProcessMemory_d4ec {
  strings:
    $key_d4ec = { 83 9e [2] b1 bc [2] b7 89 [2] 99 89 [2] a6 95 }

  condition:
    any of them
}