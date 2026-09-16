rule TTP_XOR_WriteProcessMemory_da2a {
  strings:
    $key_da2a = { 8d 58 [2] bf 7a [2] b9 4f [2] 97 4f [2] a8 53 }

  condition:
    any of them
}