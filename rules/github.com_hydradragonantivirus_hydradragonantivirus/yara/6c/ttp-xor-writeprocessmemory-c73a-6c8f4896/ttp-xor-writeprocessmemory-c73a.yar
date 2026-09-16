rule TTP_XOR_WriteProcessMemory_c73a {
  strings:
    $key_c73a = { 90 48 [2] a2 6a [2] a4 5f [2] 8a 5f [2] b5 43 }

  condition:
    any of them
}