rule TTP_XOR_WriteProcessMemory_c66a {
  strings:
    $key_c66a = { 91 18 [2] a3 3a [2] a5 0f [2] 8b 0f [2] b4 13 }

  condition:
    any of them
}