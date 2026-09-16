rule TTP_XOR_WriteProcessMemory_c64a {
  strings:
    $key_c64a = { 91 38 [2] a3 1a [2] a5 2f [2] 8b 2f [2] b4 33 }

  condition:
    any of them
}