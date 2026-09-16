rule TTP_XOR_WriteProcessMemory_d34a {
  strings:
    $key_d34a = { 84 38 [2] b6 1a [2] b0 2f [2] 9e 2f [2] a1 33 }

  condition:
    any of them
}