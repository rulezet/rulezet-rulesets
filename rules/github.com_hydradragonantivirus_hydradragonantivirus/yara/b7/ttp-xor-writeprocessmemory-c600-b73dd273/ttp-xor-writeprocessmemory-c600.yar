rule TTP_XOR_WriteProcessMemory_c600 {
  strings:
    $key_c600 = { 91 72 [2] a3 50 [2] a5 65 [2] 8b 65 [2] b4 79 }

  condition:
    any of them
}