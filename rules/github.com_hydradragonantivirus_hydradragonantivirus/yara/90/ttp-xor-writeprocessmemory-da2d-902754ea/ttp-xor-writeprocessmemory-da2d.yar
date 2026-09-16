rule TTP_XOR_WriteProcessMemory_da2d {
  strings:
    $key_da2d = { 8d 5f [2] bf 7d [2] b9 48 [2] 97 48 [2] a8 54 }

  condition:
    any of them
}