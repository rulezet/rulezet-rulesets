rule TTP_XOR_WriteProcessMemory_c1f5 {
  strings:
    $key_c1f5 = { 96 87 [2] a4 a5 [2] a2 90 [2] 8c 90 [2] b3 8c }

  condition:
    any of them
}