rule TTP_XOR_WriteProcessMemory_c44a {
  strings:
    $key_c44a = { 93 38 [2] a1 1a [2] a7 2f [2] 89 2f [2] b6 33 }

  condition:
    any of them
}