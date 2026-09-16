rule TTP_XOR_WriteProcessMemory_da5d {
  strings:
    $key_da5d = { 8d 2f [2] bf 0d [2] b9 38 [2] 97 38 [2] a8 24 }

  condition:
    any of them
}