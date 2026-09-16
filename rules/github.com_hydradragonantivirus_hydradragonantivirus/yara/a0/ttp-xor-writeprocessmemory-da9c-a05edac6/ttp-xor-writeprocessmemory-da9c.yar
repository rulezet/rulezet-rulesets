rule TTP_XOR_WriteProcessMemory_da9c {
  strings:
    $key_da9c = { 8d ee [2] bf cc [2] b9 f9 [2] 97 f9 [2] a8 e5 }

  condition:
    any of them
}