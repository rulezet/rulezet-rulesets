rule TTP_XOR_WriteProcessMemory_da7d {
  strings:
    $key_da7d = { 8d 0f [2] bf 2d [2] b9 18 [2] 97 18 [2] a8 04 }

  condition:
    any of them
}