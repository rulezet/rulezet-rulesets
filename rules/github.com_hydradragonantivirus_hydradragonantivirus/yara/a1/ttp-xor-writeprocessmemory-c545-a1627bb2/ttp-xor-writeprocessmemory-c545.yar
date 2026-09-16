rule TTP_XOR_WriteProcessMemory_c545 {
  strings:
    $key_c545 = { 92 37 [2] a0 15 [2] a6 20 [2] 88 20 [2] b7 3c }

  condition:
    any of them
}