rule TTP_XOR_WriteProcessMemory_da12 {
  strings:
    $key_da12 = { 8d 60 [2] bf 42 [2] b9 77 [2] 97 77 [2] a8 6b }

  condition:
    any of them
}