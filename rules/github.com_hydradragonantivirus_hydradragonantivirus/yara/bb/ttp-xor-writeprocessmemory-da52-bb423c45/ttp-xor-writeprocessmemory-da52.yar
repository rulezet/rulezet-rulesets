rule TTP_XOR_WriteProcessMemory_da52 {
  strings:
    $key_da52 = { 8d 20 [2] bf 02 [2] b9 37 [2] 97 37 [2] a8 2b }

  condition:
    any of them
}