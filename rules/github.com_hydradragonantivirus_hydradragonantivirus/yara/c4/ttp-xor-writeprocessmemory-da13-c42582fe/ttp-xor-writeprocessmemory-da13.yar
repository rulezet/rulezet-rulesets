rule TTP_XOR_WriteProcessMemory_da13 {
  strings:
    $key_da13 = { 8d 61 [2] bf 43 [2] b9 76 [2] 97 76 [2] a8 6a }

  condition:
    any of them
}