rule TTP_XOR_WriteProcessMemory_c62a {
  strings:
    $key_c62a = { 91 58 [2] a3 7a [2] a5 4f [2] 8b 4f [2] b4 53 }

  condition:
    any of them
}