rule TTP_XOR_WriteProcessMemory_c529 {
  strings:
    $key_c529 = { 92 5b [2] a0 79 [2] a6 4c [2] 88 4c [2] b7 50 }

  condition:
    any of them
}