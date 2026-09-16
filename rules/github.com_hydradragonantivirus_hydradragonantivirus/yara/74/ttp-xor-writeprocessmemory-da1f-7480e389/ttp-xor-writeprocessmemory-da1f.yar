rule TTP_XOR_WriteProcessMemory_da1f {
  strings:
    $key_da1f = { 8d 6d [2] bf 4f [2] b9 7a [2] 97 7a [2] a8 66 }

  condition:
    any of them
}