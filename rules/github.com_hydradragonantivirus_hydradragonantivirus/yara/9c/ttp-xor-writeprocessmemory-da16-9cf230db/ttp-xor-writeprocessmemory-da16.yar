rule TTP_XOR_WriteProcessMemory_da16 {
  strings:
    $key_da16 = { 8d 64 [2] bf 46 [2] b9 73 [2] 97 73 [2] a8 6f }

  condition:
    any of them
}