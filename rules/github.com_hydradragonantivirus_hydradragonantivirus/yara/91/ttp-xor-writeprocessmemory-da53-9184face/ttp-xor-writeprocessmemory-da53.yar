rule TTP_XOR_WriteProcessMemory_da53 {
  strings:
    $key_da53 = { 8d 21 [2] bf 03 [2] b9 36 [2] 97 36 [2] a8 2a }

  condition:
    any of them
}