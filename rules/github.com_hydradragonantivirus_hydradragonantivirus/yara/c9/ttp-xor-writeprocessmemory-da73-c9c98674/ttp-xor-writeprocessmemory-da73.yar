rule TTP_XOR_WriteProcessMemory_da73 {
  strings:
    $key_da73 = { 8d 01 [2] bf 23 [2] b9 16 [2] 97 16 [2] a8 0a }

  condition:
    any of them
}