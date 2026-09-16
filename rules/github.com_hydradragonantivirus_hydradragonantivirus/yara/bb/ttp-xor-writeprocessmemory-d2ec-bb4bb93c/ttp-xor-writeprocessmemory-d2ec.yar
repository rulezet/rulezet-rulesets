rule TTP_XOR_WriteProcessMemory_d2ec {
  strings:
    $key_d2ec = { 85 9e [2] b7 bc [2] b1 89 [2] 9f 89 [2] a0 95 }

  condition:
    any of them
}