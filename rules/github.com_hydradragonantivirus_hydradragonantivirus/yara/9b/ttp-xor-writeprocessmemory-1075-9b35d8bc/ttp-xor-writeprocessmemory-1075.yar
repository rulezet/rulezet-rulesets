rule TTP_XOR_WriteProcessMemory_1075 {
  strings:
    $key_1075 = { 47 07 [2] 75 25 [2] 73 10 [2] 5d 10 [2] 62 0c }

  condition:
    any of them
}