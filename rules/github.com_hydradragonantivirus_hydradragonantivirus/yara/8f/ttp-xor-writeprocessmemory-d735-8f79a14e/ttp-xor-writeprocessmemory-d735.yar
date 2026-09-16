rule TTP_XOR_WriteProcessMemory_d735 {
  strings:
    $key_d735 = { 80 47 [2] b2 65 [2] b4 50 [2] 9a 50 [2] a5 4c }

  condition:
    any of them
}