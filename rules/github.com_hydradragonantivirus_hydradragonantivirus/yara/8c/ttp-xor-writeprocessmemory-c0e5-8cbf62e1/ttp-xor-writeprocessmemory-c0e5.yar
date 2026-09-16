rule TTP_XOR_WriteProcessMemory_c0e5 {
  strings:
    $key_c0e5 = { 97 97 [2] a5 b5 [2] a3 80 [2] 8d 80 [2] b2 9c }

  condition:
    any of them
}