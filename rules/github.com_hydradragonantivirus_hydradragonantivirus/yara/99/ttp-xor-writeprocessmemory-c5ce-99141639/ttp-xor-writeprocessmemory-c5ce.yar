rule TTP_XOR_WriteProcessMemory_c5ce {
  strings:
    $key_c5ce = { 92 bc [2] a0 9e [2] a6 ab [2] 88 ab [2] b7 b7 }

  condition:
    any of them
}