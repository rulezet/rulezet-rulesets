rule TTP_XOR_WriteProcessMemory_c475 {
  strings:
    $key_c475 = { 93 07 [2] a1 25 [2] a7 10 [2] 89 10 [2] b6 0c }

  condition:
    any of them
}