rule TTP_XOR_WriteProcessMemory_da9a {
  strings:
    $key_da9a = { 8d e8 [2] bf ca [2] b9 ff [2] 97 ff [2] a8 e3 }

  condition:
    any of them
}