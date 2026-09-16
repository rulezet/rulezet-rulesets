rule TTP_XOR_WriteProcessMemory_c05a {
  strings:
    $key_c05a = { 97 28 [2] a5 0a [2] a3 3f [2] 8d 3f [2] b2 23 }

  condition:
    any of them
}