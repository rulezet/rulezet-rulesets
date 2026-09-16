rule TTP_XOR_WriteProcessMemory_c6e5 {
  strings:
    $key_c6e5 = { 91 97 [2] a3 b5 [2] a5 80 [2] 8b 80 [2] b4 9c }

  condition:
    any of them
}