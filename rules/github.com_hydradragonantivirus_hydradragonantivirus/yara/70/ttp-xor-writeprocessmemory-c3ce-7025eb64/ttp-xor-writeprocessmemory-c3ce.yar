rule TTP_XOR_WriteProcessMemory_c3ce {
  strings:
    $key_c3ce = { 94 bc [2] a6 9e [2] a0 ab [2] 8e ab [2] b1 b7 }

  condition:
    any of them
}