rule TTP_XOR_WriteProcessMemory_da68 {
  strings:
    $key_da68 = { 8d 1a [2] bf 38 [2] b9 0d [2] 97 0d [2] a8 11 }

  condition:
    any of them
}