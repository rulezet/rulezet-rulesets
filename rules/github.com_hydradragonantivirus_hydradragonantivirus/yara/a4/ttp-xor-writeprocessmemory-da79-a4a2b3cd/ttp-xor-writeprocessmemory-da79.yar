rule TTP_XOR_WriteProcessMemory_da79 {
  strings:
    $key_da79 = { 8d 0b [2] bf 29 [2] b9 1c [2] 97 1c [2] a8 00 }

  condition:
    any of them
}