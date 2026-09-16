rule TTP_XOR_WriteProcessMemory_da46 {
  strings:
    $key_da46 = { 8d 34 [2] bf 16 [2] b9 23 [2] 97 23 [2] a8 3f }

  condition:
    any of them
}