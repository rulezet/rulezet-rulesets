rule TTP_XOR_WriteProcessMemory_da9d {
  strings:
    $key_da9d = { 8d ef [2] bf cd [2] b9 f8 [2] 97 f8 [2] a8 e4 }

  condition:
    any of them
}