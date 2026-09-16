rule TTP_XOR_WriteProcessMemory_d675 {
  strings:
    $key_d675 = { 81 07 [2] b3 25 [2] b5 10 [2] 9b 10 [2] a4 0c }

  condition:
    any of them
}