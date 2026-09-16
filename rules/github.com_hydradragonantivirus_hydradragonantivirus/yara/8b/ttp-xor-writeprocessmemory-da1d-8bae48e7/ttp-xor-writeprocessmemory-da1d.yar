rule TTP_XOR_WriteProcessMemory_da1d {
  strings:
    $key_da1d = { 8d 6f [2] bf 4d [2] b9 78 [2] 97 78 [2] a8 64 }

  condition:
    any of them
}