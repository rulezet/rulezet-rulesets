rule TTP_XOR_WriteProcessMemory_da72 {
  strings:
    $key_da72 = { 8d 00 [2] bf 22 [2] b9 17 [2] 97 17 [2] a8 0b }

  condition:
    any of them
}