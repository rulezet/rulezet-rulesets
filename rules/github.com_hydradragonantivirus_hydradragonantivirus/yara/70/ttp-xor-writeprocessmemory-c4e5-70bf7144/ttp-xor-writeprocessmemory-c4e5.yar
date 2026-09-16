rule TTP_XOR_WriteProcessMemory_c4e5 {
  strings:
    $key_c4e5 = { 93 97 [2] a1 b5 [2] a7 80 [2] 89 80 [2] b6 9c }

  condition:
    any of them
}