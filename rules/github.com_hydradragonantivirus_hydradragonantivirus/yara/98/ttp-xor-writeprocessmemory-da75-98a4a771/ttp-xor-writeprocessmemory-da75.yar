rule TTP_XOR_WriteProcessMemory_da75 {
  strings:
    $key_da75 = { 8d 07 [2] bf 25 [2] b9 10 [2] 97 10 [2] a8 0c }

  condition:
    any of them
}