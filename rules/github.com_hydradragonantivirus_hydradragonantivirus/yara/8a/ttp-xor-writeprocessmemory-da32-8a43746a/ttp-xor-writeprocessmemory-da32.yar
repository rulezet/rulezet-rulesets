rule TTP_XOR_WriteProcessMemory_da32 {
  strings:
    $key_da32 = { 8d 40 [2] bf 62 [2] b9 57 [2] 97 57 [2] a8 4b }

  condition:
    any of them
}