rule TTP_XOR_WriteProcessMemory_da65 {
  strings:
    $key_da65 = { 8d 17 [2] bf 35 [2] b9 00 [2] 97 00 [2] a8 1c }

  condition:
    any of them
}