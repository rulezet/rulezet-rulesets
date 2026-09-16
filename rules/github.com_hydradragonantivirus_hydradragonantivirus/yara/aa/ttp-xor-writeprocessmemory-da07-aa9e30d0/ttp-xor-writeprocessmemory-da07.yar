rule TTP_XOR_WriteProcessMemory_da07 {
  strings:
    $key_da07 = { 8d 75 [2] bf 57 [2] b9 62 [2] 97 62 [2] a8 7e }

  condition:
    any of them
}