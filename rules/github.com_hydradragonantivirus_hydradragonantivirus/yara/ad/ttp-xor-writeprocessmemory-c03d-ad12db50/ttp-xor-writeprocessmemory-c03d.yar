rule TTP_XOR_WriteProcessMemory_c03d {
  strings:
    $key_c03d = { 97 4f [2] a5 6d [2] a3 58 [2] 8d 58 [2] b2 44 }

  condition:
    any of them
}