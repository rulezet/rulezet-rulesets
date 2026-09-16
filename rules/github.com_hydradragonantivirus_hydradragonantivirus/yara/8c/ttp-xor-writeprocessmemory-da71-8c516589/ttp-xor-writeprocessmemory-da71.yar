rule TTP_XOR_WriteProcessMemory_da71 {
  strings:
    $key_da71 = { 8d 03 [2] bf 21 [2] b9 14 [2] 97 14 [2] a8 08 }

  condition:
    any of them
}