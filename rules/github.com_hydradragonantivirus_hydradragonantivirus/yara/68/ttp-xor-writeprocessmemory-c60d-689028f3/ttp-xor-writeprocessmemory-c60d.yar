rule TTP_XOR_WriteProcessMemory_c60d {
  strings:
    $key_c60d = { 91 7f [2] a3 5d [2] a5 68 [2] 8b 68 [2] b4 74 }

  condition:
    any of them
}