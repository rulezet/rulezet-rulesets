rule TTP_XOR_WriteProcessMemory_da06 {
  strings:
    $key_da06 = { 8d 74 [2] bf 56 [2] b9 63 [2] 97 63 [2] a8 7f }

  condition:
    any of them
}