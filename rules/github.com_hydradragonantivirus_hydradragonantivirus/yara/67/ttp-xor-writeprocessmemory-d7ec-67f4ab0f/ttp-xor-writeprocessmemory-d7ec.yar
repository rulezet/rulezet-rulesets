rule TTP_XOR_WriteProcessMemory_d7ec {
  strings:
    $key_d7ec = { 80 9e [2] b2 bc [2] b4 89 [2] 9a 89 [2] a5 95 }

  condition:
    any of them
}