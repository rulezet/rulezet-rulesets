rule TTP_XOR_WriteProcessMemory_d645 {
  strings:
    $key_d645 = { 81 37 [2] b3 15 [2] b5 20 [2] 9b 20 [2] a4 3c }

  condition:
    any of them
}