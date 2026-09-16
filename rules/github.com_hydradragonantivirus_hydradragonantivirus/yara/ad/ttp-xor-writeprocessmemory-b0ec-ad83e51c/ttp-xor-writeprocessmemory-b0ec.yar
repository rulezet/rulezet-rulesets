rule TTP_XOR_WriteProcessMemory_b0ec {
  strings:
    $key_b0ec = { e7 9e [2] d5 bc [2] d3 89 [2] fd 89 [2] c2 95 }

  condition:
    any of them
}