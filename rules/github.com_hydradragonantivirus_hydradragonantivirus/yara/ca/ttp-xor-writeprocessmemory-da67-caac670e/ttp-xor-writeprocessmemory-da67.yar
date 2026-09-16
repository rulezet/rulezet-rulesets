rule TTP_XOR_WriteProcessMemory_da67 {
  strings:
    $key_da67 = { 8d 15 [2] bf 37 [2] b9 02 [2] 97 02 [2] a8 1e }

  condition:
    any of them
}