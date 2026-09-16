rule TTP_XOR_WriteProcessMemory_c6ec {
  strings:
    $key_c6ec = { 91 9e [2] a3 bc [2] a5 89 [2] 8b 89 [2] b4 95 }

  condition:
    any of them
}