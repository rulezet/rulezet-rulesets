rule TTP_XOR_WriteProcessMemory_c115 {
  strings:
    $key_c115 = { 96 67 [2] a4 45 [2] a2 70 [2] 8c 70 [2] b3 6c }

  condition:
    any of them
}