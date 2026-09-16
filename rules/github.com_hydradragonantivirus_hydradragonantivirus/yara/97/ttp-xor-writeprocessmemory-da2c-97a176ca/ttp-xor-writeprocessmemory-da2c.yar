rule TTP_XOR_WriteProcessMemory_da2c {
  strings:
    $key_da2c = { 8d 5e [2] bf 7c [2] b9 49 [2] 97 49 [2] a8 55 }

  condition:
    any of them
}