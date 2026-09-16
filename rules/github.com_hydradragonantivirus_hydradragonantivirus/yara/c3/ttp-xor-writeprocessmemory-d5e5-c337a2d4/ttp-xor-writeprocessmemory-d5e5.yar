rule TTP_XOR_WriteProcessMemory_d5e5 {
  strings:
    $key_d5e5 = { 82 97 [2] b0 b5 [2] b6 80 [2] 98 80 [2] a7 9c }

  condition:
    any of them
}