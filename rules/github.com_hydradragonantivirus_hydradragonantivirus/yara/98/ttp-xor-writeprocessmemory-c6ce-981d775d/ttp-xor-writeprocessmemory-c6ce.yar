rule TTP_XOR_WriteProcessMemory_c6ce {
  strings:
    $key_c6ce = { 91 bc [2] a3 9e [2] a5 ab [2] 8b ab [2] b4 b7 }

  condition:
    any of them
}