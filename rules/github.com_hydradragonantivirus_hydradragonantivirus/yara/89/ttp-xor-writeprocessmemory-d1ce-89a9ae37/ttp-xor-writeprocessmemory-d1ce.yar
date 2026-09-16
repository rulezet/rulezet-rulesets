rule TTP_XOR_WriteProcessMemory_d1ce {
  strings:
    $key_d1ce = { 86 bc [2] b4 9e [2] b2 ab [2] 9c ab [2] a3 b7 }

  condition:
    any of them
}