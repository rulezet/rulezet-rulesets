rule TTP_XOR_WriteProcessMemory_da10 {
  strings:
    $key_da10 = { 8d 62 [2] bf 40 [2] b9 75 [2] 97 75 [2] a8 69 }

  condition:
    any of them
}