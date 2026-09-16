rule TTP_XOR_WriteProcessMemory_3cc7 {
  strings:
    $key_3cc7 = { 6b b5 [2] 59 97 [2] 5f a2 [2] 71 a2 [2] 4e be }

  condition:
    any of them
}