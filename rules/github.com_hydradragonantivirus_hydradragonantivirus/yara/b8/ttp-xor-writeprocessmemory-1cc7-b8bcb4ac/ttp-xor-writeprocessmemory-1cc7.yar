rule TTP_XOR_WriteProcessMemory_1cc7 {
  strings:
    $key_1cc7 = { 4b b5 [2] 79 97 [2] 7f a2 [2] 51 a2 [2] 6e be }

  condition:
    any of them
}