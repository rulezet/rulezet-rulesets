rule TTP_XOR_WriteProcessMemory_da47 {
  strings:
    $key_da47 = { 8d 35 [2] bf 17 [2] b9 22 [2] 97 22 [2] a8 3e }

  condition:
    any of them
}