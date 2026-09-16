rule TTP_XOR_WriteProcessMemory_da5f {
  strings:
    $key_da5f = { 8d 2d [2] bf 0f [2] b9 3a [2] 97 3a [2] a8 26 }

  condition:
    any of them
}