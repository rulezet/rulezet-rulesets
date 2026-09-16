rule TTP_XOR_WriteProcessMemory_da20 {
  strings:
    $key_da20 = { 8d 52 [2] bf 70 [2] b9 45 [2] 97 45 [2] a8 59 }

  condition:
    any of them
}