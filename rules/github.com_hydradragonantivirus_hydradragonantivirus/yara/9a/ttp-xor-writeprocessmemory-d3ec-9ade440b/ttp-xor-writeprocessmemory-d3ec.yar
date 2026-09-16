rule TTP_XOR_WriteProcessMemory_d3ec {
  strings:
    $key_d3ec = { 84 9e [2] b6 bc [2] b0 89 [2] 9e 89 [2] a1 95 }

  condition:
    any of them
}