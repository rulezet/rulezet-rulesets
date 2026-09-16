rule TTP_XOR_WriteProcessMemory_c415 {
  strings:
    $key_c415 = { 93 67 [2] a1 45 [2] a7 70 [2] 89 70 [2] b6 6c }

  condition:
    any of them
}