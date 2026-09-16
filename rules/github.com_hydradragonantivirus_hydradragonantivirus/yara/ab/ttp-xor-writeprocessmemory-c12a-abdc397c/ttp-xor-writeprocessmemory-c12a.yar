rule TTP_XOR_WriteProcessMemory_c12a {
  strings:
    $key_c12a = { 96 58 [2] a4 7a [2] a2 4f [2] 8c 4f [2] b3 53 }

  condition:
    any of them
}