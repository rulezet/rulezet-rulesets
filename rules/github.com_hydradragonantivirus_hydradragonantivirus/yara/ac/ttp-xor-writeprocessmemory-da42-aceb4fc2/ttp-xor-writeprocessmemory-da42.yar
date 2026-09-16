rule TTP_XOR_WriteProcessMemory_da42 {
  strings:
    $key_da42 = { 8d 30 [2] bf 12 [2] b9 27 [2] 97 27 [2] a8 3b }

  condition:
    any of them
}