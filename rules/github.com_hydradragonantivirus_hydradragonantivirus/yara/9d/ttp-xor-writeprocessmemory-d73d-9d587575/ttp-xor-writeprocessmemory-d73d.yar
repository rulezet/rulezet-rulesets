rule TTP_XOR_WriteProcessMemory_d73d {
  strings:
    $key_d73d = { 80 4f [2] b2 6d [2] b4 58 [2] 9a 58 [2] a5 44 }

  condition:
    any of them
}