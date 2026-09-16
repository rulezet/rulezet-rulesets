rule TTP_XOR_WriteProcessMemory_c7f5 {
  strings:
    $key_c7f5 = { 90 87 [2] a2 a5 [2] a4 90 [2] 8a 90 [2] b5 8c }

  condition:
    any of them
}