rule TTP_XOR_WriteProcessMemory_da30 {
  strings:
    $key_da30 = { 8d 42 [2] bf 60 [2] b9 55 [2] 97 55 [2] a8 49 }

  condition:
    any of them
}