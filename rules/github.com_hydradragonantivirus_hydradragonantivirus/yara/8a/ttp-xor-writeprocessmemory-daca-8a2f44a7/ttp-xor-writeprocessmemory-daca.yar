rule TTP_XOR_WriteProcessMemory_daca {
  strings:
    $key_daca = { 8d b8 [2] bf 9a [2] b9 af [2] 97 af [2] a8 b3 }

  condition:
    any of them
}