rule TTP_XOR_WriteProcessMemory_d71f {
  strings:
    $key_d71f = { 80 6d [2] b2 4f [2] b4 7a [2] 9a 7a [2] a5 66 }

  condition:
    any of them
}