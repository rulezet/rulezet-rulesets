rule TTP_XOR_WriteProcessMemory_c42a {
  strings:
    $key_c42a = { 93 58 [2] a1 7a [2] a7 4f [2] 89 4f [2] b6 53 }

  condition:
    any of them
}