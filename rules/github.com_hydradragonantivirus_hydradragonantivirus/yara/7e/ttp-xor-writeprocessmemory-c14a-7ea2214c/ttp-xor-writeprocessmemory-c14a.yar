rule TTP_XOR_WriteProcessMemory_c14a {
  strings:
    $key_c14a = { 96 38 [2] a4 1a [2] a2 2f [2] 8c 2f [2] b3 33 }

  condition:
    any of them
}