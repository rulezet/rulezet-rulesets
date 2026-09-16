rule TTP_XOR_WriteProcessMemory_d74a {
  strings:
    $key_d74a = { 80 38 [2] b2 1a [2] b4 2f [2] 9a 2f [2] a5 33 }

  condition:
    any of them
}