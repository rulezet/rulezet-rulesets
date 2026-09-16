rule TTP_XOR_WriteProcessMemory_c1ce {
  strings:
    $key_c1ce = { 96 bc [2] a4 9e [2] a2 ab [2] 8c ab [2] b3 b7 }

  condition:
    any of them
}